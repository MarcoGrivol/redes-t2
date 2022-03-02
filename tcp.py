import asyncio, time
from tcputils import *
from secrets import randbits

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            new_seq = randbits(31) + FLAGS_SYN + 1
            new_ack = seq_no + 1
            conexao = self.conexoes[id_conexao] = Conexao(
                self, 
                id_conexao,
                seq_no=new_seq,
                ack_no=new_ack
            )
            handshake = make_header(
                self.porta, 
                src_port, 
                seq_no=new_seq,
                ack_no=new_ack, 
                flags=FLAGS_SYN | FLAGS_ACK
            )
            handshake = fix_checksum(handshake, dst_addr, src_addr)
            self.rede.enviar(handshake, src_addr)
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))

    def close(self, id_conexao):
        del self.conexoes[id_conexao]


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.src_addr, self.src_port, self.dst_addr, self.dst_port = \
            id_conexao[2], id_conexao[3], id_conexao[0], id_conexao[1]
        self.seq_no = seq_no
        self.ack_no = ack_no
        self.callback = None
        self.timer = None
        self.pktsQ = []
        self.sent_pkts = []
        self.timeout_interval = 1
        self.start_time = None
        self.estimated_rtt = None
        self.dev_rtt = None
        self.cwnd = 1

    def _timeout(self):
        self.cwnd = max(1, self.cwnd // 2)
        for i, (pkt, _) in enumerate(self.sent_pkts):
            self.sent_pkts[i] = (pkt, None) # remove timing since it was not recvd
        pkt, _ = self.sent_pkts[0]
        self.servidor.rede.enviar(pkt, self.dst_addr)
        self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self._timeout)

    def _get_idx(self, acked_pkt):
        max_idx = None
        for i, (pkt, _) in enumerate(self.sent_pkts):
            _, _, seq_not_acked, _, _, _, _, _ = read_header(pkt)
            if acked_pkt > seq_not_acked:
                max_idx = i
        return max_idx

    def _calc_timeout_interval(self, t0, t1):
        sample_rtt = t1 - t0
        if self.estimated_rtt is None:
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2
            return self.estimated_rtt + 4 * self.dev_rtt
        self.estimated_rtt = (1 - 0.125) * self.estimated_rtt + 0.125 * sample_rtt
        self.dev_rtt = (1 - 0.25) * self.dev_rtt + 0.25 * abs(sample_rtt - self.estimated_rtt)
        return self.estimated_rtt + 4 * self.dev_rtt
            
    def _ack_pkt(self, ack_no):
        if len(self.sent_pkts) == 0:
            return
        self.cwnd += 1
        idx = self._get_idx(ack_no)
        _, t0 = self.sent_pkts[idx]
        del self.sent_pkts[:idx + 1]
        if t0 is not None:
            self.timeout_interval = self._calc_timeout_interval(t0, time.time())
        if len(self.sent_pkts) == 0:
            self.timer.cancel()
            self._send_window()

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # print('-----------------------------------')
        # print('recebido payload: %r' % payload[:25])
        # print('self:', self.seq_no, self.ack_no)
        # print('rcvd:', seq_no, ack_no)
        # print('len', len(self.sent_pkts))
        if self.ack_no != seq_no:
            return
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.ack_no += 1
            payload = b''
            package_header = make_header(self.src_port, self.dst_port, self.seq_no, self.ack_no, FLAGS_ACK)
            package_header = fix_checksum(package_header, self.src_addr, self.dst_addr)
            self.servidor.rede.enviar(package_header, self.dst_addr)
            self.callback(self, payload)
        elif len(payload) != 0:
            self.ack_no += len(payload)
            package_header = make_header(self.src_port, self.dst_port, self.seq_no, self.ack_no, FLAGS_ACK)
            package_header = fix_checksum(package_header, self.src_addr, self.dst_addr)
            self.servidor.rede.enviar(package_header, self.dst_addr)
            self.callback(self, payload)

        if len(self.sent_pkts) != 0:
            self._ack_pkt(ack_no)

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def _send_window(self):
        if len(self.pktsQ) == 0:
            return
        i = 0
        while i < self.cwnd and len(self.pktsQ) != 0:
            package = self.pktsQ.pop(0)
            self.sent_pkts.append((package, time.time()))
            _, _, seq, ack, _, _, _, _ = read_header(package)
            self.servidor.rede.enviar(package, self.dst_addr)
            i += 1
        if self.timer is not None:
            self.timer.cancel()
        self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self._timeout)

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        while len(dados) != 0:
            package_header = make_header(
                self.src_port, self.dst_port, self.seq_no + 1, self.ack_no, FLAGS_ACK
            )
            package = fix_checksum(package_header + dados[:MSS], self.src_addr, self.dst_addr)
            self.pktsQ.append(package)
            self.seq_no += len(dados[:MSS])
            dados = dados[MSS:]
        self._send_window()
            


    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        package_header = make_header(
            self.src_port, self.dst_port, self.seq_no + 1, self.ack_no, FLAGS_FIN
        )
        package = fix_checksum(package_header, self.src_addr, self.dst_addr)
        self.servidor.rede.enviar(package, self.dst_addr)
        self.servidor.close(self.id_conexao)
