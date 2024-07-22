from OpenSSL import SSL, crypto
import socket

def getPEMFile(hostname, port):
    # Establish a connection and fetch the certificate
    dst = (hostname, port)
    ctx = SSL.Context(SSL.TLSv1_2_METHOD)
    s = socket.create_connection(dst)
    s = SSL.Connection(ctx, s)
    s.set_connect_state()
    s.set_tlsext_host_name(str.encode(dst[0]))

    s.sendall(str.encode('HEAD / HTTP/1.0\n\n'))

    peerCertChain = s.get_peer_cert_chain()
    pemFile = ''

    # Convert certificates to PEM format
    for cert in peerCertChain:
        pemFile += crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")

    return pemFile
