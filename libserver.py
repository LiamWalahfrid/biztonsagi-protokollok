import sys
import selectors
import json
import io
import struct
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Util import Padding


class Message:
    def __init__(self, selector, sock, addr):
        self.selector = selector
        self.sock = sock
        self.addr = addr
        self._recv_buffer = b""
        self._send_buffer = b""
        self.header_len = None
        self.header = None

        self.key = None

        self._header_len = 16   # header: 16 bytes
        self._authtag_len = 12  # we'd like to use a 12-byte long authentication tag
        self._sqn = 0
        self._rcvsqn = 0
        self.header = None
        self._type = b''

        self.request = None
        self.response_created = False

    def _set_selector_events_mask(self, mode):
        """Set selector to listen for events: mode is 'r', 'w', or 'rw'."""
        if mode == "r":
            events = selectors.EVENT_READ
        elif mode == "w":
            events = selectors.EVENT_WRITE
        elif mode == "rw":
            events = selectors.EVENT_READ | selectors.EVENT_WRITE
        else:
            raise ValueError(f"Invalid events mask mode {mode!r}.")
        self.selector.modify(self.sock, events, data=self)

    def _read(self):
        try:
            # Should be ready to read
            data = self.sock.recv(4096)
        except BlockingIOError:
            # Resource temporarily unavailable (errno EWOULDBLOCK)
            pass
        else:
            if data:
                self._recv_buffer += data
            else:
                raise RuntimeError("Peer closed.")

    def _write(self):
        if self._send_buffer:
            try:
                # Should be ready to write
                sent = self.sock.send(self._send_buffer)
            except BlockingIOError:
                # Resource temporarily unavailable (errno EWOULDBLOCK)
                pass
            else:
                self._send_buffer = self._send_buffer[sent:]
                # Close when the buffer is drained. The response has been sent.
                if sent and not self._send_buffer:
                    self.close()

    def _create_message(
        self, *, payload
    ):
        
        # compute payload_length and set authtag_length
        payload_length = len(payload)
    
        # compute message length...
        # header: 16 bytes
        # payload: payload_length
        # authtag: authtag_length
        msg_length = self._header_len + payload_length + self._authtag_len

        # create header
        ver = b'\x01\x00'                                     # protocol version 1.0
        typ = b'\x00\x10'                                     # message type 1
        len = msg_length.to_bytes(2, byteorder='big')         # message length (encoded on 2 bytes)
        sqn = (1).to_bytes(2, byteorder='big')                # next message sequence number (encoded on 2 bytes)
        rnd = Random.get_random_bytes(6)                      # 6-byte long random value
        rsv = b'\x00\x00'                                     # reserved bytes

        header = ver + typ + len + sqn + rnd + rsv

        # encrypt the payload and compute the authentication tag over the header and the payload
        # with AES in GCM mode using nonce = sqn + rnd
        nonce = sqn + rnd

        AE = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=self._authtag_len)
        AE.update(header)
        encrypted_payload, authtag = AE.encrypt_and_digest(payload)

        msg = header + encrypted_payload + authtag
        
        return msg

    def process_events(self, mask):
        if mask & selectors.EVENT_READ:
            self.read()
        if mask & selectors.EVENT_WRITE:
            self.write()

    def read(self):
        self._read()
        
        self.process_request()

    def write(self):
        if self.request:
            if not self.response_created:
                self.create_response()

        self._write()

    def close(self):
        print(f"Closing connection to {self.addr}")
        try:
            self.selector.unregister(self.sock)
        except Exception as e:
            print(
                f"Error: selector.unregister() exception for "
                f"{self.addr}: {e!r}"
            )

        try:
            self.sock.close()
        except OSError as e:
            print(f"Error: socket.close() exception for {self.addr}: {e!r}")
        finally:
            # Delete reference to socket object for garbage collection
            self.sock = None

    def process_request(self):
        msg = self._recv_buffer
        # parse the message msg
        
        header = msg[0:16]
        ver = header[0:2]      # version is encoded on 2 bytes 
        typ = header[2:4]         # type is encoded on 2 byte 
        len = header[4:6]       # msg length is encoded on 2 bytes 
        sqn = header[6:8]          # msg sqn is encoded on 2 bytes 
        rnd = header[8:14]         # random is encoded on 6 bytes 
        rsv = header[14:16]        # reserved is encoded on 2 bytes

        # check the msg length
        msg_len = len(msg)
        if msg_len != int.from_bytes(len, byteorder='big'):
            print("Warning: Message length value in header is wrong!")
            self.close()

        # check the sequence number
        print("Expecting sequence number " + str(self._rcvsqn + 1) + " or larger...")
        sndsqn = int.from_bytes(sqn, byteorder='big')
        if (sndsqn <= self._rcvsqn):
            print("Error: Message sequence number is too old!")
            print("Processing completed.")
            self.close()    
        print("Sequence number verification is successful.")

        if typ == b'\x00\x00':

            mtp_msg = msg[:-256]
            etk = msg[-256:]                # header is 16 bytes long
            authtag = mtp_msg[-12:]               # last 12 bytes is the authtag
            encrypted_payload = mtp_msg[16:-12]   # encrypted payload is between header and authtag
            
            # create an RSA cipher object
            RSAcipher = PKCS1_OAEP.new(...)
            self.key = RSAcipher.decrypt(etk)

        else:
            authtag = msg[-12:]
            encrypted_payload = msg[16:-12]

        # verify and decrypt the encrypted payload
        print("Decryption and authentication tag verification is attempted...")
        nonce = sqn + rnd
        AE = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        AE.update(header)
        try:
            payload = AE.decrypt_and_verify(encrypted_payload, authtag)
        except Exception as e:
            print("Error: Operation failed!")
            print("Processing completed.")
            sys.exit(1)
        print("Operation was successful: message is intact, content is decrypted.")

        self._rcvsqn += 1
        
        # TODO: login protocol

        print(payload)
        
        self._recv_buffer = self._recv_buffer[msg_len:]
        
        # Set selector to listen for write events, we're done reading.
        self._set_selector_events_mask("w")

    def create_response(self):
        response = ''
        message = self._create_message(**response)
        self.response_created = True
        self._send_buffer += message
