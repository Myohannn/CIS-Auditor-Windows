import socket

def is_port_open(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)  # Timeout for the operation
    try:
        sock.connect((ip, port))
        sock.shutdown(socket.SHUT_RDWR)
        return True
    except:
        return False
    finally:
        sock.close()

# Test the function
ip_address = '192.168.56.103'  # Replace with your server's IP address
port = 445  # Replace with your port
print(is_port_open(ip_address, port))
