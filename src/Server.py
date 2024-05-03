import socket
import os
import utils
import threading

def send_messages(client_socket, AES_key):
    while True:
        message = input()
        print("Sent Message:", message)
        encrypted_message = utils.encrypt_message(message, AES_key)
        utils.send_encrypted_message(client_socket, encrypted_message)

def receive_messages(client_socket, AES_key):
    while True:
        received_message = utils.receive_encrypted_message(client_socket)
        decrypted_message = utils.decrypt_message(received_message, AES_key)
        print("Received Message:", decrypted_message)

def main():
    qDH = 0
    alphaDH = 0
    qGL = 0
    alphaGL = 0

    server_socket = None
    client_socket = None

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('localhost', 12345))
        server_socket.listen(1)

        client_socket, addr = server_socket.accept()

        with open("Parameters.txt", "r") as file:
            for line in file:
                if line.strip() == "DH":
                    qDH, alphaDH = map(int, file.readline().split())
                elif line.strip() == "ElGamal":
                    qGL, alphaGL = map(int, file.readline().split())

        print(f"DH q: {qDH}, alpha: {alphaDH}")
        print(f"ElGamal q: {qGL}, alpha: {alphaGL}")

        XADH = utils.generate_private_key(qDH)
        YADH = utils.mod_pow(alphaDH, XADH, qDH)
        XAGL = utils.generate_private_key(qGL)
        YAGL = utils.mod_pow(alphaGL, XAGL, qGL)

        print(f"YAGL: {YAGL}")

        client_response = utils.receive_string(client_socket)
        print(f"Client Response: {client_response}")

        utils.send_string(client_socket, "hello from the server")
        client_YAGL = utils.receive_long_value(client_socket)
        print(f"Client EL Gamal Key: {client_YAGL}")

        utils.send_long_value(client_socket, YAGL)

        signature = utils.compute_el_gamal_signature(YADH, qGL, alphaGL, XAGL)
        S1, S2 = signature

        print(f"Server Signature: {YADH} {S1} {S2}")

        data_to_send = f"{YADH},{S1},{S2}"
        utils.send_string(client_socket, data_to_send)

        

        received_data = utils.receive_string(client_socket)
        client_YADH, client_S1, client_S2 = map(int, received_data.split(','))

        print(f"Client Signature: {client_YADH} {client_S1} {client_S2}")
       
        is_valid_signature = utils.verify_signature(alphaGL, client_YADH, qGL, client_YAGL, client_S1, client_S2)
        if not is_valid_signature:
            utils.send_string(client_socket, "Invalid signature. Connection terminated.")
            server_socket.close()
            print("Invalid signature. Connection terminated.")
            
         
        Shared_Key=utils.compute_shared_key(client_YADH,XADH,qDH)
        print("Server Shared key:",Shared_Key)
        AES_Key=utils.generate_aes_key(Shared_Key)
        print("Server AES key:",AES_Key)
    
    
        send_thread = threading.Thread(target=send_messages, args=(client_socket, AES_Key))
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket, AES_Key))

        send_thread.start()
        receive_thread.start()

        send_thread.join()
        receive_thread.join()     

    except KeyboardInterrupt:
        print("Keyboard interrupt detected. Exiting gracefully.")
    except Exception as e:
        print(e)

    finally:
        if client_socket:
            client_socket.close()
        if server_socket:
            server_socket.close()

if __name__ == "__main__":
    main()
