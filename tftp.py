# Don't forget to change this file's name before submission.
import sys
import os
import enum
import struct
import socket


class TftpProcessor(object):
    """
    Implements logic for a TFTP client.
    The input to this object is a received UDP packet,
    the output is the packets to be written to the socket.

    This class MUST NOT know anything about the existing sockets
    its input and outputs are byte arrays ONLY.

    Store the output packets in a buffer (some list) in this class
    the function get_next_output_packet returns the first item in
    the packets to be sent.

    This class is also responsible for reading/writing files to the
    hard disk.

    Failing to comply with those requirements will invalidate
    your submission.

    Feel free to add more functions to this class as long as
    those functions don't interact with sockets nor inputs from
    user/sockets. For example, you can add functions that you
    think they are "private" only. Private functions in Python
    start with an "_", check the example below
    """

    class TftpPacketType(enum.Enum):
        """
        Represents a TFTP packet type add the missing types here and
        modify the existing values as necessary.
        """
        RRQ = 1,  # Read Request
        WRQ = 2,  # Write Request
        DATA = 3,  # Data
        ACK = 4,  # Acknowledge
        ERROR = 5,  # Error
        OACK = 6  # Option Acknowledge

        def __str__(self):
            return '%s' % self.value

    class Modes(enum.Enum):
        NETASCII = 0,
        OCTET = 1

    file_data = None
    operation = ''
    local_filename = ''

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        pass

    def Error(self, i):
        switcher = {
            0: 'Not defined, see error message (if any)',
            1: 'File not found',
            2: 'Access violation',
            3: 'Disk full or allocation exceeded',
            4: 'Illegal TFTP operation',
            5: 'Unknown transfer ID',
            6: 'File already esxists',
            7: 'No such user'
        }
        return switcher.get(i, "error")

    def IncrementBlock(self, recvData, block):
        if recvData[3] == 255:
            if recvData[2] < 255:
                block[0] = recvData[2] + 1
                block[1] = 0
            else:
                block[0] = 0
                block[1] = 0
        else:
            block[1] = recvData[3] + 1
        return block

    def Ack(self, block1, block2):
        byte_arr = bytearray(4)
        byte_arr[0] = 0
        byte_arr[1] = int(str(self.TftpPacketType.ACK))  # ACK
        byte_arr[2] = block1
        byte_arr[3] = block2
        return byte_arr

    def addtail(self, data, block0, block1):
        a = bytearray(len(data) + 4)
        a[0] = 0
        a[1] = int(str(self.TftpPacketType.DATA))  # data
        a[2] = block0
        a[3] = block1
        for i in range(4, len(data) + 4):
            a[i] = data[i - 4]
        return a

    def load_file_bytes(self, data):
        self.local_filename = data
        _file = open(self.local_filename, 'rb')
        _file_content = _file.read()
        self.file_data = _file_content
        print('Loaded {0} bytes.', len(_file_content))
        pass

    block = [0, 0]
    packetNumber = 0
    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        opcode = self._parse_udp_packet(packet_data)
        out_packet = bytearray(0)
        if(self.operation == 'push'):
            if opcode == int(str(self.TftpPacketType.ACK)) and (((packet_data[2] << 8) & 0xff00) | packet_data[3]) == self.packetNumber:  # ACK
                #print('OPCODE: ACK')
                self.packetNumber += 1
                block = self.IncrementBlock(packet_data, self.block)
                out_packet = self.addtail(packet_source.read(512), self.block[0], self.block[1])
                pass
            elif opcode == int(str(self.TftpPacketType.ERROR)):  # ERROR
                #print('OPCODE: ERROR')
                print('ERROR: ', self.Error(packet_data[3]))
                return
            else:
                print('UNKNOWN OP CODE ' + str(opCode))
            if len(out_packet) < 516:
                return
            pass
        elif self.operation == 'pull':
            if opcode == (int)(str(self.TftpPacketType.DATA)):  # DATA
                #print('OPCODE: DATA')
                packet_source.write(packet_data[4:])
                out_packet = self.Ack(packet_data[2], packet_data[3])
                pass
            elif opcode == (int)(str(self.TftpPacketType.OACK)):  # OACK
                #print('OPCODE: OACK')
                out_packet = self.Ack(0, 0)
                pass
            elif opcode == (int)(str(TftpProcessor.TftpPacketType.ERROR)):  # ERROR
                #print('OPCODE: ERROR')
                print('ERROR: ', self.Error(packet_data[3]))
                return
            else:
                print('UNKNOWN OP CODE ' + str(opCode))
            if len(packet_data) < 516 and opcode == (int)(str(self.TftpPacketType.DATA)):
                return
            pass
        else:
            print('Unknown operation')
            return
        # This shouldn't change.
        self.packet_buffer.append(out_packet)
        pass

    def _do_some_logic(self, in_packet):
        pass

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        return packet_bytes[1]

    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.

        For example;
        s_socket.send(tftp_processor.get_next_output_packet())

        Leave this function as is.
        """
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.

        Leave this function as is.
        """
        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server):  # done.
        # code = self.TftpPacketType.RRQ
        # print(chr(int(self.TftpPacketType.WRQ)))
        self.operation = 'pull'
        code = str(self.TftpPacketType.RRQ)
        nullchar = '\0'
        packetStr = ""
        packetStr += nullchar + chr(int(code))  # chr(1)
        packetStr += file_path_on_server + nullchar + 'octet' + nullchar
        packetStr += 'blksize' + nullchar + '512' + nullchar + 'tsize' + nullchar
        packetStr += '0' + nullchar + 'timeout' + nullchar + '100' + nullchar
        #print(packetStr)
        return struct.pack(str(len(packetStr)) + 's', bytes(packetStr, 'utf-8'))

    def upload_file(self, file_path_on_server):  # done.
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        self.operation = 'push'
        code = str(self.TftpPacketType.WRQ)
        nullchar = '\0'
        packetStr = ""
        packetStr += nullchar + chr(int(code))  # chr(2)
        packetStr += file_path_on_server + nullchar + 'octet' + nullchar
        packetStr += 'blksize\0512' + nullchar + 'tsize' + nullchar
        packetStr += str(len(self.file_data)) + nullchar + 'timeout' + nullchar + '10' + nullchar
        #print(packetStr)
        return struct.pack(str(len(packetStr)) + 's', bytes(packetStr, 'utf-8'))


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        pass
    processor = TftpProcessor()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_address = ('127.0.0.1', 69)

    if operation == 'push':
        processor.load_file_bytes(file_name)
        request_packet = processor.upload_file(file_name)  # 'remote23.txt')
        sock.sendto(request_packet, sock_address)
        (received_packet, (sock_address)) = sock.recvfrom(512)
        file = open(file_name, 'rb')
        while True:
            processor.process_udp_packet(received_packet, file)
            if processor.has_pending_packets_to_be_sent() == False:
                break
            sock.sendto(processor.get_next_output_packet(), sock_address)
            received_packet, sock_address = sock.recvfrom(512)
        pass
        print('PUSH REQUEST: DONE')
        # end of push.
    elif operation == 'pull':
        data = processor.request_file(file_name)
        sock.sendto(data, sock_address)
        (received_packet, (sock_address)) = sock.recvfrom(512)
        file = open(file_name, 'wb')
        while True:
            processor.process_udp_packet(received_packet, file)
            if processor.has_pending_packets_to_be_sent() == False:
                break
            sock.sendto(processor.get_next_output_packet(), sock_address)
            received_packet, sock_address = sock.recvfrom(516)
        pass
        file.close()
        print('PULL REQUEST: DONE')


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


processor = None
sock = None
sock_address = None


def main():
    """
     Write your code above this function.
    if you need the command line arguments
    """
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")  # push or pull.
    file_name = get_arg(3, "darkt.txt")
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
