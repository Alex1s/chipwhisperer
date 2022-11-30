import chipwhisperer.capture.targets.SimpleSerial2 as SimpleSerial2
import struct
import importlib
import time
from typing import List
import numpy as np
import logging
dilithium = importlib.import_module("python-dilithium.dilithium")
dilithium.generic = importlib.import_module("python-dilithium.dilithium.generic")
dilithium_params = dilithium.__params

class LogToExceptionHandler(logging.NullHandler):
    def __init__():
        super(LogToExceptionHandler, self).__init__()
        self.setLevel(logging.NOTSET)

    @property
    def warning_or_higher_logged(self) -> bool:
        return self.__warning_or_higher_logged

    @warning_or_higher_logged.setter
    def warning_or_higher_logged(self, value: bool) -> None:
        if type(value) is not bool:
            raise ValueError(f'warning_or_higher_logged has to by of type bool; got: {type(value)}')
        self.__warning_or_higher_logged = value

    def __init__(self):
        __warning_or_higher_logged = False

    def handle(self, record):
        if record.levelno >= logging.WARNING:
            self.__warning_or_higher_logged = True

class SimpleSerial2Dilithium(SimpleSerial2):
    __handler = LogToExceptionHandler()
    __ALGORITHMS = [2, 3, 5]
    __MAX_PAYLOAD_LENGTH = 128 #64 #120 #128 #249
    
    __COMMAND_ALGORITHM = 'q'
    __COMMAND_SET_SECRET_KEY = 'k'
    __COMMAND_SIGN = 'e'
    __FIRST_ERR_RATE_PAYLOAD249_ITER100 = [ 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 1., 1., 3., 3., 19., 12., 11., 7., 10., 5., 5., 9., 2., 4., 2., 1., 0., 1., 0., 0., 0., 2., 0., 0., 0., 0., 0., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.]
    __FIRST_ERROR_RATE_PAYLOAD128_ITER10000 = [0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 0., 0., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.]
    
    def __send_cmd_long(self, command: str, payload: bytes, timeout: int = 2000) -> None:
        assert len(command) == 1
        
        bytes_sent = 0
        bytes_left = len(payload)
        for i in range(9999999):
            next_packet_len = self.__MAX_PAYLOAD_LENGTH if bytes_left > self.__MAX_PAYLOAD_LENGTH else bytes_left
            if next_packet_len == 0:
                break
            next_packet = payload[i * self.__MAX_PAYLOAD_LENGTH:i * self.__MAX_PAYLOAD_LENGTH + next_packet_len]
            
            self.send_cmd(command, i, next_packet)
            response = self.simpleserial_read(cmd='r', timeout=timeout)
            assert response == b'ok', f'received error: {bytes(response)} at packet {i} with len {next_packet_len}'

            bytes_sent += next_packet_len
            bytes_left -= next_packet_len

    def __simpleserial_read_long(self, length: int, command: str = None, timeout: int = 2000) -> bytes:
        if command is not None:
            assert len(command) == 1
            
        num_full_reads = length // self.__MAX_PAYLOAD_LENGTH
        length_last_read = length % self.__MAX_PAYLOAD_LENGTH
            
        buf = b''
        for i in range(num_full_reads):
            reply = self.simpleserial_read(cmd=command, timeout=timeout)
            assert reply is not None, f'i={i}; num_full_reads={num_full_reads}'
            assert len(reply) == self.__MAX_PAYLOAD_LENGTH
            buf += reply
        
        reply = self.simpleserial_read(cmd=command, timeout=timeout)
        assert reply is not None
        assert len(reply) == length_last_read
        buf += reply
        
        assert len(buf) == length
        
        return buf
    
    
    @property
    def algorithm(self) -> int:
        return self.__algorithm
    
    @algorithm.setter
    def algorithm(self, a: int):
        if a not in self.__ALGORITHMS:
            raise ValueError()
        # self.send_cmd(self.__COMMAND_ALGORITHM, 0, struct.pack('B', a))
        # response = self.simpleserial_read(cmd='r')
        # assert response is not None
        # assert response.startswith(b'set_alg ok: ' + struct.pack('B', a))
        self.__algorithm = a
        
    @property
    def secret_key(self) -> bytes:
        return self.__secret_key
    
    @property
    def crypto_bytes(self) -> int:
        return dilithium_params[self.__algorithm]['CRYPTO_SECRETKEYBYTES']
    
    @secret_key.setter
    def secret_key(self, s: bytes):
        if len(s) != self.crypto_bytes:
            raise ValueError(f'Expected secret key of length {self.crypto_bytes} but got {len(s)}')
        # self.send_cmd_long(self.__COMMAND_SECRET_KEY, s)
        self.__secre_key = s
        
    
    @property
    def scope(self):
        return self.__scope
    
    
    @scope.setter
    def scope(self, s):
        assert s is not None
        self.__scope = s
        
    def sign(self, message: bytes) -> bytes:
        if len(message) > self.__MAX_PAYLOAD_LENGTH:
            raise ValueError()
        self.send_cmd(self.__COMMAND_SIGN, 0, message)
        reply = self.__simpleserial_read_long(self.crypto_bytes, 'r')
        assert reply == dilithium.generic.signature(message, self.secret_key)
        return reply
    
    def reboot_flush(self):            
        self.scope.io.nrst = False
        time.sleep(0.05)
        self.scope.io.nrst = "high_z"
        time.sleep(0.05)
        #Flush garbage too
        self.flush()
        
    
    
    def check_error_rate(self, n: int) -> List[int]:
        assert n > 0
        expected = b'set_alg ok: 3' + 100 * b'Hello'
        expected = expected[:self.__MAX_PAYLOAD_LENGTH]
        
        def get_index_of_first_diff_bytes(a: bytes, b: bytes) -> int:
            if a == b:
                return None
            
            minlen = min(len(a), len(b))
            assert minlen >= 1
            for i in range(1, minlen):
                if a[:i] != b[:i]:
                    return i - 1
                
        dist = np.zeros(len(expected))
        for i in range(n):
            self.send_cmd(self.__COMMAND_ALGORITHM, 0, struct.pack('B', 3))
            try:
                response = self.simpleserial_read(cmd='r', timeout=100)
                assert bytes(response) == expected, f'got: {bytes(response)}; expected: {expected}'
            except BlockingIOError:
                #assert response is not None, f'i={i}'
                #assert response.startswith(b'set_alg ok: 3'), f'i={i}; got: {bytes(response)}'
                diff_idx = get_index_of_first_diff_bytes(response, expected)
                if diff_idx is None:
                    assert response == expected
                else:
                    assert response != expected
                if response == expected:
                    self.__logger.info('We noticed a transmission error but actually the data is fine; error in packet header / trailer?; be worried if this occurs often')
                else:
                    dist[diff_idx] += 1;
        return dist
    
    def simpleserial_read(self, cmd=None, pay_len=None, end='\n', timeout=250, ack=True):
        self.__handler.warning_or_higher_logged = False
        ret = super(SimpleSerial2Dilithium, self).simpleserial_read(cmd=cmd, pay_len=pay_len, end=end, timeout=timeout, ack=ack)
        if self.__handler.warning_or_higher_logged:
            raise BlockingIOError('target logger logged a warning during simpleserial_read')
        return ret

    def simpleserial_read_until_success(self, cmd=None, pay_len=None, end='\n', timeout=250, ack=True):
        while True:
            try:
                ret = self.simpleserial_read(cmd=cmd, pay_len=pay_len, end=end, timeout=timeout, ack=ack)
                return ret
            except BlockingIOError as e:
                self.__logger.info(f'got an BlockingIOError exception: {e}; trying again ...')
                self.flush()

    def __init__(self, scope = None, algorithm: int = 2, secret_key: bytes = None):
        SimpleSerial2.__init__(self)
        
        self.__scope = None
        self.__algorithm = algorithm
        self.algorithm = algorithm
        # self.__crypto_bytes = dilithium_params[self.__algorithm]['CRYPTO_SERETKEYBTES']
        
        if secret_key is None:
            dilithium.generic.pseudorandombytes_seed(b'attack-shuffling-countermeasure-keypair')
            public_key, secret_key = dilithium.generic.keypair(nist_security_level=self.algorithm)
        self.__secret_key = None
        self.secret_key = secret_key
        
        if scope is not None:
            self.__scope.default_setup()

        self.__logger = logging.getLogger('SimpleSerial2Dilithium')
        self.__logger.setLevel(logging.NOTSET) # does this actually do something?
        self.__logger.debug('SimpleSerial2Dilithium logger says hello!')

        self.__handler = SimpleSerial2Dilithium.__handler
        self.__target_logger = logging.getLogger("ChipWhisperer Target")
        if self.__handler not in self.__target_logger.handlers:
            self.__target_logger.addHandler(self.__handler)
        self.__handler.setLevel(logging.NOTSET)


