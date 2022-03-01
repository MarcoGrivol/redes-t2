import asyncio, time
from random import sample
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
        self.buffer = []
        self.timeout_interval = 1
        self.start_time = None
        self.estimated_rtt = None
        self.dev_rtt = None
        self.cwnd = 1

    def _timeout(self):
        if self.cwnd > 1:
            self.cwnd = self.cwnd // 2
        package, _ = self.buffer[0]
        self.buffer[0] = (package, None)
        self.servidor.rede.enviar(package, self.dst_addr)
        self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self._timeout)
        # package, _ = self.buffer[0]
        # self.buffer[0] = (package, None)
        # # _, _, seq, ack, flags, _, _, _ = read_header(package)
        # self.servidor.rede.enviar(package, self.dst_addr)

    def _get_idx_inQ(self, acked_pkt):
        for i, (pkt, _) in enumerate(self.buffer):
            _, _, seq_not_acked, _, _, _, _, _ = read_header(pkt)
            if acked_pkt >= seq_not_acked:
                return i
        return None

    def _calc_timeout_interval(self, t0, t1):
        sample_rtt = t1 - t0
        if self.estimated_rtt is None:
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2
            return self.estimated_rtt + 4 * self.dev_rtt
        self.estimated_rtt = (1 - 0.125) * self.estimated_rtt + 0.125 * sample_rtt
        self.dev_rtt = (1 - 0.25) * self.dev_rtt + 0.25 * abs(sample_rtt - self.estimated_rtt)
        return self.estimated_rtt + 4 * self.dev_rtt
            

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        print('!!!', seq_no, ack_no, len(payload))
        if self.ack_no != seq_no:
            return
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.ack_no += 1
            payload = b''
        elif len(payload) == 0:
            if len(self.buffer) == 0:
                return
            # get idx of package from queue buff and remove
            self.timer.cancel()
            idx = self._get_idx_inQ(ack_no)
            _, t0 = self.buffer[idx]
            if t0 is not None:
                self.timeout_interval = self._calc_timeout_interval(t0, time.time())
                self.cwnd += 1
            del self.buffer[:idx + 1]
            return
        else:
            self.ack_no += len(payload)
        print('recebido payload: %r' % payload[:25])
        print('self:', self.seq_no, self.ack_no)
        print('rcvd:', seq_no, ack_no, '\n')
        package_header = make_header(
            self.src_port,
            self.dst_port,
            self.seq_no,
            self.ack_no,
            FLAGS_ACK
        )
        package_header = fix_checksum(package_header, self.src_addr, self.dst_addr)
        self.servidor.rede.enviar(package_header, self.dst_addr)
        self.callback(self, payload)
        if self.timer is not None:
            self.timer.cancel()

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        print(f'Enviando dados ({len(dados)}): seq_no: {self.seq_no + 1} ack_no: {self.ack_no} - {dados[:5]}')
        package_header = make_header(
            self.src_port, self.dst_port, self.seq_no + 1, self.ack_no, FLAGS_ACK
        )
        package = fix_checksum(package_header + dados[:MSS], self.src_addr, self.dst_addr)
        self.servidor.rede.enviar(package, self.dst_addr)
        self.buffer.append((package, time.time()))
        self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self._timeout)
        self.seq_no += len(dados[:MSS])

        if len(dados) > MSS:
            self.enviar(dados[MSS:])


    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        print('Fechando conexao')
        package_header = make_header(
            self.src_port, self.dst_port, self.seq_no + 1, self.ack_no, FLAGS_FIN
        )
        package = fix_checksum(package_header, self.src_addr, self.dst_addr)
        self.servidor.rede.enviar(package, self.dst_addr)
        self.servidor.close(self.id_conexao)
