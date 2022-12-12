import chipwhisperer.capture.targets.SimpleSerial2 as SimpleSerial2
import struct
import importlib
import time
from typing import List
import numpy as np
import logging
import math
from dilithium import _params as dilithium_params # is "python-dilithium" in path?
from dilithium import Dilithium # is "python-dilithium" in path?

class TargetIOError(BlockingIOError):
    @property
    def data(self):
        return self.__data

    def __init__(self, message: str, data):
        super().__init__(message)
        self.__data = data

class TargetTimeoutError(TargetIOError):
    def __init__(self):
        super().__init__('Target cleanly timed out while generating a signature', b'')


class LogToExceptionHandler(logging.NullHandler):
    def __init__():
        super().__init__()
        self.setLevel(logging.NOTSET)

    @property
    def warning_or_higher_logged(self) -> bool:
        return self.__warning_or_higher_logged

    @property
    def records_warning_or_higher(self) -> list:
        return [record for record in self.__records_warning_or_higher]

    def reset(self) -> None:
        self.__warning_or_higher_logged = False
        self.__records_warning_or_higher = []

    def __init__(self):
        self.__warning_or_higher_logged = False
        self.__records_warning_or_higher = []

    def handle(self, record):
        if record.levelno >= logging.WARNING:
            self.__warning_or_higher_logged = True
            self.__records_warning_or_higher += [record]

class SimpleSerial2Dilithium(SimpleSerial2):
    __handler = LogToExceptionHandler()
    __ALGORITHMS = [2, 3, 5]
    __MAX_PAYLOAD_LENGTH = 128 #64 #120 #128 #249
    
    __COMMAND_ALGORITHM = 'q'
    __COMMAND_SET_SECRET_KEY = 'k'
    __COMMAND_SIGN = 'e'
    __COMMAND_GET_SIGN = 'g'
    __COMMAND_LOOP = 'l'
    __COMMAND_GET_POLY = 'n'
    __FIRST_ERR_RATE_PAYLOAD249_ITER100 = [ 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 1., 1., 3., 3., 19., 12., 11., 7., 10., 5., 5., 9., 2., 4., 2., 1., 0., 1., 0., 0., 0., 2., 0., 0., 0., 0., 0., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.]
    __FIRST_ERROR_RATE_PAYLOAD128_ITER10000 = [0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 0., 0., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.]
    __FIRST_ERROR_RATE_PAYLOAD128_ITER100000 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 2, 0, 1, 3, 0, 1, 1, 1, 0, 0, 0, 0, 0, 3, 0, 1, 0, 2, 0, 0, 2, 1, 0, 0, 0, 1, 0, 0, 1, 0, 2, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0]
    # 100 Dilithium (2) signature timings in seconds of messages (0x0000 - 0x0064)
    __SIG_TIMINGS = [1.8345985412597656, 0.571202278137207, 0.5727174282073975, 2.44435453414917, 1.9954373836517334, 1.956618309020996, 1.0284478664398193, 0.5720925331115723, 1.0222575664520264, 0.5756478309631348, 3.327014446258545, 1.1550006866455078, 3.5656371116638184, 1.4125359058380127, 1.2258155345916748, 0.5754551887512207, 0.5706188678741455, 2.6741480827331543, 1.2207884788513184, 0.569699764251709, 1.8295707702636719, 2.4150185585021973, 2.5315682888031006, 1.6380705833435059, 0.5689265727996826, 0.7610783576965332, 0.800501823425293, 2.897522211074829, 1.539381504058838, 1.148653507232666, 0.5714447498321533, 2.256739377975464, 0.795245885848999, 0.956822395324707, 0.5665726661682129, 0.5721073150634766, 1.150632381439209, 1.2155184745788574, 1.6022050380706787, 0.9530470371246338, 0.7947635650634766, 1.220771312713623, 1.7636890411376953, 0.7999839782714844, 2.0266835689544678, 2.9747705459594727, 1.5745739936828613, 0.5741910934448242, 1.4473426342010498, 1.153580665588379, 0.5740790367126465, 0.7645726203918457, 0.5718286037445068, 3.671562433242798, 1.5743498802185059, 2.4453606605529785, 0.5700263977050781, 0.7969129085540771, 0.5690975189208984, 1.2237257957458496, 0.571495532989502, 0.9935479164123535, 0.7666583061218262, 1.0304381847381592, 0.8014285564422607, 0.5709078311920166, 0.7657623291015625, 0.7964329719543457, 1.832737922668457, 0.5714242458343506, 1.1860861778259277, 0.571995735168457, 0.7650182247161865, 1.0285441875457764, 2.029315710067749, 0.987626314163208, 0.7646205425262451, 2.2466177940368652, 1.6047735214233398, 0.7635841369628906, 0.5692150592803955, 0.7618019580841064, 1.6753244400024414, 0.9920835494995117, 0.5694153308868408, 0.7975795269012451, 1.4073009490966797, 2.9902737140655518, 0.5741786956787109, 0.8005082607269287, 2.445647716522217, 0.5705244541168213, 0.993781566619873, 0.7978324890136719, 3.0634548664093018, 0.7647135257720947, 0.7613015174865723, 1.8281018733978271, 0.5725083351135254, 0.993952751159668]

    
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
    def crypto_secretkeybytes(self) -> int:
        return dilithium_params[self.__algorithm]['CRYPTO_SECRETKEYBYTES']

    @property
    def crypto_bytes(self) -> int:
        return dilithium_params[self.__algorithm]['CRYPTO_BYTES']

    @property
    def polyz_packedbytes(self) -> int:
        return dilithium_params[self.__algorithm]['POLYZ_PACKEDBYTES']
    
    @secret_key.setter
    def secret_key(self, s: bytes):
        if len(s) != self.crypto_secretkeybytes:
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
        
    def sign(self, message: bytes, timeout: int = 10000) -> None:
        ok_reply = b'sign ok'
        if len(message) > self.__MAX_PAYLOAD_LENGTH:
            raise ValueError()
        self.send_cmd(self.__COMMAND_SIGN, 0, message)
        reply = self.simpleserial_read('r', len(ok_reply), timeout=timeout)
        assert reply == ok_reply

    def loop_send(self) -> None:
        self.send_cmd(self.__COMMAND_LOOP, 0, b'')

    def loop_recv(self, timeout=10) -> None:
        ok_reply = b'loop ok'
        reply = self.simpleserial_read('r', len(ok_reply), timeout=timeout)
        if reply != ok_reply:
            raise TargetIOError(f'Did not receive expected reply "{ok_reply} but instead got {reply}."', reply)

    def loop(self, timeout: int = 100) -> None:
        self.loop_send()
        self.loop_recv(timeout=timeout)

    def get_poly(self, max_num_retries: int = None) -> bytes:
        num_packets = math.ceil(self.polyz_packedbytes / self.__MAX_PAYLOAD_LENGTH)
        len_last_packet = self.polyz_packedbytes % self.__MAX_PAYLOAD_LENGTH if self.polyz_packedbytes % self.__MAX_PAYLOAD_LENGTH else self.__MAX_PAYLOAD_LENGTH
        dat = b''
        for i in range(num_packets - 1):
            dat += self.simpleserial_cmd_until_success(self.__COMMAND_GET_POLY, i, b'\xAA', cmd_read='r', pay_len=self.__MAX_PAYLOAD_LENGTH, max_num_retries=max_num_retries)
        dat += self.simpleserial_cmd_until_success(self.__COMMAND_GET_POLY, num_packets - 1, b'\xAA', cmd_read='r', pay_len=len_last_packet)
        return dat

    def get_sig(self) -> bytes:
        num_packets = math.ceil(self.crypto_bytes / self.__MAX_PAYLOAD_LENGTH)
        len_last_packet = self.crypto_bytes % self.__MAX_PAYLOAD_LENGTH if self.crypto_bytes % self.__MAX_PAYLOAD_LENGTH else self.__MAX_PAYLOAD_LENGTH
        dat = b''
        for i in range(num_packets - 1):
            dat += self.simpleserial_cmd_until_success(self.__COMMAND_GET_SIGN, i, b'\xAA', cmd_read='r', pay_len=self.__MAX_PAYLOAD_LENGTH)
        dat += self.simpleserial_cmd_until_success(self.__COMMAND_GET_SIGN, num_packets - 1, b'\xAA', cmd_read='r', pay_len=len_last_packet)
        return dat

    def read_until_blocking(self, pattern: bytes, timeout=1000) -> bytes:
        """yes, blocking; so that it is fast"""
        buf = b''
        start = time.time()
        while time.time() - start < timeout / 1000:
            onecharstring = self.read(num_char=1, timeout=1)
            assert type(onecharstring) is str
            assert len(onecharstring) in [0, 1]
            for char in onecharstring:
                buf += bytes([ord(char)]) # is that the correct way to convert that string? why is it even a string -,-
                if buf.endswith(pattern):
                    return buf
        raise TimeoutError(f'read_until_blocking timed out after {time.time() - start} s. (timeout={timeout / 1000}). Read until now: {buf}')

    def reboot_flush(self, timeout=2000):
        self.scope.io.nrst = False
        time.sleep(0.05)
        self.scope.io.nrst = "high_z"
        # why is the overhead byte \x0b? Is it always that value? We will see ...
        data_read = self.read_until_blocking(b'\x0bb\x07boot ok\xc1\x00', timeout=timeout) # simpleserial_put('b', sizeof("boot ok") - 1, "boot ok");
        return data_read

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
            except TargetIOError as e:
                response = e.data
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
        self.__handler.reset()
        ret = super(SimpleSerial2Dilithium, self).simpleserial_read(cmd=cmd, pay_len=pay_len, end=end, timeout=timeout, ack=ack)
        if self.__handler.warning_or_higher_logged:
            # let us somehow classify these error ffs -,-
            if len(self.__handler.records_warning_or_higher) == 1 and self.__handler.records_warning_or_higher[0].msg == 'Read timed out: ':
                raise TargetTimeoutError()
            raise TargetIOError(f'target logger logged a warning during simpleserial_read: {[r.msg for r in self.__handler.records_warning_or_higher]}', ret)
        return ret

    def simpleserial_cmd_until_success(self, cmd, scmd, data, cmd_read=None, pay_len=None, end='\n', timeout=250, ack=True, max_num_retries : int = None):
        num_retries = 0
        while max_num_retries is None or num_retries < max_num_retries:
            try:
                self.send_cmd(cmd, scmd, data)
                ret = self.simpleserial_read(cmd=cmd_read, pay_len=pay_len, end=end, timeout=timeout, ack=ack)
                return ret
            except TargetIOError as e:
                self.__logger.info(f'got an BlockingIOError exception: {e}; trying again ...')
                num_retries += 1
                self.flush()
        raise TargetIOError(f'Giving up reading from target after {num_retries} failed attempts.');

    def filter_msgs_one_iter(self, messages: [bytes], threshold: int = 700):
        good_messages = []
        for message in messages:
            try:
                self.sign(message, timeout=threshold)
                good_messages += [message]
            except TargetTimeoutError as e:
                print(e)
                print('Continuing, all fine ...')
                self.reboot_flush()
        return good_messages

    def __init__(self, scope = None, algorithm: int = 2, secret_key: bytes = None):
        super().__init__()
        
        self.__scope = None
        self.__algorithm = algorithm
        self.algorithm = algorithm
        self.__d = Dilithium(self.algorithm)
        # self.__crypto_bytes = dilithium_params[self.__algorithm]['CRYPTO_SERETKEYBTES']
        
        if secret_key is None:
            self.__d.pseudorandombytes_seed(b'attack-shuffling-countermeasure-keypair')
            public_key, secret_key = self.__d.keypair()
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


