import socket
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

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect(('localhost', 12345))

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

            utils.send_string(client_socket, "hello from the client")
            server_response = utils.receive_string(client_socket)
            print(f"Server Response: {server_response}")

            utils.send_long_value(client_socket, YAGL)
            server_YAGL = utils.receive_long_value(client_socket)
            print(f"Server EL Gamal Key: {server_YAGL}")

            signature = utils.compute_el_gamal_signature(YADH, qGL, alphaGL, XAGL)
            S1, S2 = signature

            print(f"Client Signature: {YADH} {S1} {S2}")

            received_data = utils.receive_string(client_socket)
            server_YADH, server_S1, server_S2 = map(int, received_data.split(','))

            print(f"Server Signature: {server_YADH} {server_S1} {server_S2}")

            is_valid_signature = utils.verify_signature(alphaGL, server_YADH, qGL, server_YAGL, server_S1, server_S2)
            if not is_valid_signature:
                client_socket.close()
                print("Invalid signature. Connection terminated.")

            data_to_send = f"{YADH},{S1},{S2}"
            utils.send_string(client_socket, data_to_send)

            Shared_Key = utils.compute_shared_key(server_YADH, XADH, qDH)
            print("Client Shared key:", Shared_Key)
            AES_Key = utils.generate_aes_key(Shared_Key)
            print("Client AES key:", AES_Key)

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

if __name__ == "__main__":
    main()
