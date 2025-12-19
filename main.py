##import socket
##import struct
##import json
##import binascii
##import subprocess
##import os
##import configparser
##import pyodbc
##from concurrent.futures import ThreadPoolExecutor
##
##from logger import Logger
##
##
##class MDVRVideoRequestHandler:
##
##    MAGIC = b"\x48\x01"
##    HEARTBEAT_ACK = b"\x48\x01\x01\x40\x00\x00\x00\x00"
##
##    def __init__(self, config_file="config.ini"):
##
##        # Load config
##        self.config = configparser.ConfigParser()
##        self.config.read(config_file)
##
##        # Logger
##        self.logger = Logger(config_file)
##
##        # Server config
##        self.port = int(self.config["SERVER"]["port"])
##        self.max_workers = int(self.config["SERVER"]["max_workers"])
##
##        # FFmpeg path
##        self.ffmpeg_path = self.config["FFMPEG"]["binary_path"]
##
##        # DB config
##        self.db_str = self.config["DATABASE"]["connection_str"]
##        self.table_video_request = self.config["DATABASE"]["table_video_request"]
##
##        # Stats
##        self.ACTIVE_CONNECTIONS = 0
##        self.TOTAL_CONNECTIONS = 0
##
##        # FFmpeg process store
##        self.FFMPEG_PROCS = {}
##
##        print(f"[CONFIG LOADED] Port={self.port} Workers={self.max_workers}")
##        self.logger.info(f"[CONFIG LOADED] Port={self.port}, Workers={self.max_workers}")
##
##    # ---------------------------------------------------------
##    # DB UPDATE: IN PROCESS
##    # ---------------------------------------------------------
##    def db_update_in_process(self, dn, ss):
##        try:
##            conn = pyodbc.connect(self.db_str)
##            cur = conn.cursor()
##
##            query = f"""
##                UPDATE {self.table_video_request}
##                SET video_download_status = '0'
##                WHERE unit_no = ? AND session_id = ?
##            """
##
##            cur.execute(query, dn, ss)
##            conn.commit()
##            conn.close()
##
##            self.logger.info(f"[DB] IN PROCESS → DN={dn} SS={ss}")
##
##        except Exception as e:
##            self.logger.error(f"[DB ERROR IN PROCESS] {e}")
##
##    # ---------------------------------------------------------
##    # DB UPDATE: COMPLETED
##    # ---------------------------------------------------------
##    def db_update_completed(self, dn, ss):
##        try:
##            conn = pyodbc.connect(self.db_str)
##            cur = conn.cursor()
##
##            query = f"""
##                UPDATE {self.table_video_request}
##                SET 
##                    video_download_status = '1',
##                    video_download_time = GETDATE()
##                WHERE unit_no = ? AND session_id = ?
##            """
##
##            cur.execute(query, dn, ss)
##            conn.commit()
##            conn.close()
##
##            self.logger.info(f"[DB] COMPLETED → DN={dn} SS={ss}")
##
##        except Exception as e:
##            self.logger.error(f"[DB ERROR COMPLETED] {e}")
##
##    # ---------------------------------------------------------
##    # START FFMPEG
##    # ---------------------------------------------------------
##    def start_ffmpeg_writer(self, dn, ss, ch):
##
##        folder = self.logger.get_video_folder(dn, ch)
##        output_file = os.path.join(folder, f"{dn}_{ss}_{ch}.mp4")
##
##        cmd = [
##            self.ffmpeg_path,
##            "-loglevel", "error",
##            "-y",
##            "-f", "h264",
##            "-i", "pipe:0",
##            "-c", "copy",
##            "-movflags", "+faststart",
##            output_file
##        ]
##
##        print(f"[FFMPEG START] {output_file}")
##        self.logger.info(f"[FFMPEG START] {output_file}")
##
##        proc = subprocess.Popen(
##            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
##        )
##
##        self.FFMPEG_PROCS[(dn, ss, ch)] = proc
##        return proc
##
##    # ---------------------------------------------------------
##    # STOP FFMPEG
##    # ---------------------------------------------------------
##    def stop_ffmpeg_writer(self, dn, ss, ch):
##
##        key = (dn, ss, ch)
##
##        if key not in self.FFMPEG_PROCS:
##            return
##
##        proc = self.FFMPEG_PROCS[key]
##
##        try:
##            proc.stdin.close()
##            proc.wait(timeout=5)
##
##            print(f"[FFMPEG COMPLETE] {dn}_{ss}_{ch}.mp4")
##            self.logger.info(f"[FFMPEG COMPLETE] {dn}_{ss}_{ch}.mp4")
##
##            # DB update = completed
##            self.db_update_completed(dn, ss)
##
##        except Exception as e:
##            err_folder = self.logger.get_error_folder(dn, ch)
##            with open(os.path.join(err_folder, "ffmpeg_error.log"), "a") as f:
##                f.write(str(e) + "\n")
##
##            self.logger.error(f"[FFMPEG ERROR] {e}")
##
##        del self.FFMPEG_PROCS[key]
##
##    # ---------------------------------------------------------
##    # ACK 4002
##    # ---------------------------------------------------------
##    def build_4002_ack(self, payload):
##        msg_id_ack = 0x4002
##        length = len(payload)
##        return (
##            b"\x48\x01"
##            + struct.pack("<H", msg_id_ack)
##            + struct.pack("<I", length)
##            + payload
##        )
##
##    # ---------------------------------------------------------
##    # CLIENT HANDLER
##    # ---------------------------------------------------------
##    def handle_client(self, client_socket, addr, conn_id):
##
##        self.ACTIVE_CONNECTIONS += 1
##        print(f"[NEW CONNECTION] #{conn_id} Active={self.ACTIVE_CONNECTIONS}")
##
##        buffer = bytearray()
##        dn = ss = ch = None
##        is_media_stream = False
##        db_flag = False  # prevents duplicate DB updates
##
##        try:
##
##            while True:
##
##                chunk = client_socket.recv(8192)
##                if not chunk:
##                    break
##
##                buffer.extend(chunk)
##
##                # ---------------- FRAME LOOP ----------------
##                while True:
##
##                    idx = buffer.find(self.MAGIC)
##                    if idx != 0:
##                        break
##
##                    if len(buffer) < 8:
##                        break
##
##                    msg_id = struct.unpack_from("<H", buffer, 2)[0]
##                    length = struct.unpack_from("<I", buffer, 4)[0]
##                    total_len = 8 + length
##
##                    if len(buffer) < total_len:
##                        break
##
##                    frame = buffer[:total_len]
##                    del buffer[:total_len]
##                    payload = frame[8:]
##
##                    # --------------------------------------------------
##                    # HEARTBEAT
##                    # --------------------------------------------------
##                    if msg_id == 0x0001:
##                        client_socket.sendall(self.HEARTBEAT_ACK)
##                        continue
##
##                    # --------------------------------------------------
##                    # SIGNAL FRAME 1002
##                    # --------------------------------------------------
##                    if msg_id == 0x1002:
##
##                        try:
##                            json_text = payload.hex()
##                            json_bytes = binascii.unhexlify(json_text)
##                            json_str = json_bytes.decode(errors="ignore").strip("\x00")
##                            json_obj = json.loads(json_str)
##
##                            dn = str(json_obj.get("dn"))
##                            ss = str(json_obj.get("ss"))
##                            ch = str(json_obj.get("ch"))
##
##                            print(f"[1002] DN={dn} SS={ss} CH={ch}")
##                            self.logger.info(f"[1002] DN={dn} SS={ss} CH={ch}")
##
##                        except Exception as e:
##                            self.logger.error(f"[1002 JSON ERROR] {e}")
##
##                        client_socket.sendall(self.build_4002_ack(payload))
##                        continue
##
##                    # --------------------------------------------------
##                    # MEDIA FRAME 0011
##                    # --------------------------------------------------
##                    if msg_id == 0x0011:
##
##                        media_data = payload[12:]
##
##                        if len(media_data) > 100:
##                            is_media_stream = True
##
##                        if not is_media_stream:
##                            continue
##
##                        if not (dn and ss and ch):
##                            continue
##
##                        # ---------------- DB UPDATE FIRST TIME ----------------
##                        if not db_flag:
##                            self.db_update_in_process(dn, ss)
##                            db_flag = True
##
##                        # ---------------- START FFMPEG ----------------
##                        key = (dn, ss, ch)
##                        if key not in self.FFMPEG_PROCS:
##                            self.start_ffmpeg_writer(dn, ss, ch)
##
##                        # ---------------- WRITE FRAME ----------------
##                        try:
##                            self.FFMPEG_PROCS[key].stdin.write(media_data)
##                        except Exception as e:
##                            err_dir = self.logger.get_error_folder(dn, ch)
##                            with open(os.path.join(err_dir, "write_error.log"), "a") as f:
##                                f.write(str(e) + "\n")
##                            self.logger.error(f"[PIPE ERROR] {e}")
##
##        except Exception as e:
##            self.logger.error(f"[CONNECTION ERROR] {e}")
##
##        finally:
##            client_socket.close()
##            self.ACTIVE_CONNECTIONS -= 1
##
##            print(f"[CLOSED] #{conn_id} Active={self.ACTIVE_CONNECTIONS}")
##            self.logger.info(f"[CLOSED] #{conn_id}")
##
##            if dn and ss and ch:
##                self.stop_ffmpeg_writer(dn, ss, ch)
##
##    # ---------------------------------------------------------
##    # SERVER START
##    # ---------------------------------------------------------
##    def start_server(self):
##
##        print(f"MDVR Video Server running on port {self.port}")
##        self.logger.info(f"Server started on port {self.port}")
##
##        executor = ThreadPoolExecutor(max_workers=self.max_workers)
##
##        server_socket = socket.socket()
##        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
##        server_socket.bind(("0.0.0.0", self.port))
##        server_socket.listen(50)
##
##        while True:
##
##            client_socket, addr = server_socket.accept()
##            self.TOTAL_CONNECTIONS += 1
##            conn_id = self.TOTAL_CONNECTIONS
##
##            print(f"[ACCEPTED] #{conn_id} from {addr}")
##            self.logger.info(f"[ACCEPTED] #{conn_id} from {addr}")
##
##            executor.submit(self.handle_client, client_socket, addr, conn_id)
##
##
##if __name__ == "__main__":
##    handler = MDVRVideoRequestHandler("config.ini")
##    handler.start_server()



# import socket
# import struct
# import json
# import binascii
# import subprocess
# import os
# import configparser
# import pyodbc
# from concurrent.futures import ThreadPoolExecutor
# from datetime import datetime

# from logger import Logger


# class MDVRVideoRequestHandler:

#     MAGIC = b"\x48\x01"
#     HEARTBEAT_ACK = b"\x48\x01\x01\x40\x00\x00\x00\x00"

#     def __init__(self, config_file="config.ini"):

#         self.config = configparser.ConfigParser()
#         self.config.read(config_file)

#         self.logger = Logger(config_file)

#         self.port = int(self.config["SERVER"]["port"])
#         self.max_workers = int(self.config["SERVER"]["max_workers"])
#         self.ffmpeg_path = self.config["FFMPEG"]["binary_path"]

#         self.db_str = self.config["DATABASE"]["connection_str"]
#         self.update_sp = self.config["DATABASE"]["update_video_req_sp"]

#         self.ACTIVE_CONNECTIONS = 0
#         self.TOTAL_CONNECTIONS = 0
#         self.FFMPEG_PROCS = {}

#         print(f"[CONFIG] Port={self.port} Workers={self.max_workers}")
#         self.logger.info(f"[CONFIG] Port={self.port} Workers={self.max_workers}")

#     # ---------------------------------------------------------
#     # PATH HELPERS (NEW)
#     # ---------------------------------------------------------
#     def get_log_directory(self, dn, ch):
#         today = datetime.now().strftime("%Y-%m-%d")

#         log_dir = os.path.join(
#             "MDVR_Video_Request_Logs",
#             today,
#             str(dn),
#             str(ch)
#         )

#         return log_dir.replace("\\", "/")

#     def get_video_file_path(self, dn, ss, ch):
#         log_dir = self.get_log_directory(dn, ch)
#         file_name = f"{dn}_{ss}_{ch}.mp4"
#         return f"{log_dir}/{file_name}"

#     # ---------------------------------------------------------
#     # BUILD 4002 ACK
#     # ---------------------------------------------------------
#     def build_4002_ack(self, payload):
#         return (
#             b"\x48\x01" +
#             struct.pack("<H", 0x4002) +
#             struct.pack("<I", len(payload)) +
#             payload
#         )

#     # ---------------------------------------------------------
#     # STORED PROCEDURE UPDATE (SAFE)
#     # ---------------------------------------------------------
#     def update_video_request_status(self, ss, dn, status, file_name=None, file_path=None):

#         sql = f"{{CALL {self.update_sp} (?,?,?,?,?)}}"
#         conn = None

#         try:
#             conn = pyodbc.connect(self.db_str, timeout=5)
#             conn.autocommit = False
#             cur = conn.cursor()

#             cur.execute(
#                 sql,
#                 str(ss),
#                 int(dn),
#                 int(status),
#                 file_name,
#                 file_path
#             )
#             conn.commit()

#             print(f"[DB UPDATE] SS={ss} DN={dn} STATUS={status}")

#         except Exception as e:
#             print(f"[DB ERROR IGNORED] {e}")

#         finally:
#             if conn:
#                 conn.close()

#     # ---------------------------------------------------------
#     # START FFMPEG
#     # ---------------------------------------------------------
#     def start_ffmpeg_writer(self, dn, ss, ch):

#         log_dir = self.get_log_directory(dn, ch)
#         os.makedirs(log_dir, exist_ok=True)

#         output_file = self.get_video_file_path(dn, ss, ch)

#         print(f"[FFMPEG START] {output_file}")

#         cmd = [
#             self.ffmpeg_path, "-y",
#             "-loglevel", "error",
#             "-f", "h264",
#             "-i", "pipe:0",
#             "-c", "copy",
#             "-movflags", "+faststart",
#             output_file
#         ]

#         proc = subprocess.Popen(
#             cmd,
#             stdin=subprocess.PIPE,
#             stdout=subprocess.PIPE,
#             stderr=subprocess.PIPE
#         )

#         self.FFMPEG_PROCS[(dn, ss, ch)] = proc

#     # ---------------------------------------------------------
#     # STOP FFMPEG
#     # ---------------------------------------------------------
#     def stop_ffmpeg_writer(self, dn, ss, ch):

#         key = (dn, ss, ch)
#         if key not in self.FFMPEG_PROCS:
#             return

#         proc = self.FFMPEG_PROCS[key]
#         file_name = f"{dn}_{ss}_{ch}.mp4"
#         log_dir = self.get_log_directory(dn, ch)

#         try:
#             proc.stdin.close()
#             proc.wait(timeout=5)

#             print(f"[DOWNLOAD COMPLETED] DN={dn} SS={ss} CH={ch}")
#             self.update_video_request_status(
#                 ss, dn, 6,
#                 file_name=file_name,
#                 file_path=log_dir
#             )

#         except Exception as e:
#             print(f"[DOWNLOAD FAILED] DN={dn} SS={ss} CH={ch}")
#             self.update_video_request_status(ss, dn, 5, None, None)

#         del self.FFMPEG_PROCS[key]

#     # ---------------------------------------------------------
#     # CLIENT HANDLER
#     # ---------------------------------------------------------
#     def handle_client(self, client_socket, addr, conn_id):

#         self.ACTIVE_CONNECTIONS += 1
#         print(f"[NEW CONNECTION] #{conn_id} from {addr}")

#         buffer = bytearray()
#         dn = ss = ch = None
#         is_media_stream = False
#         started = False

#         try:
#             while True:
#                 chunk = client_socket.recv(8192)
#                 if not chunk:
#                     break

#                 buffer.extend(chunk)

#                 while True:

#                     if buffer[:2] != self.MAGIC or len(buffer) < 8:
#                         break

#                     msg_id = struct.unpack_from("<H", buffer, 2)[0]
#                     length = struct.unpack_from("<I", buffer, 4)[0]

#                     if len(buffer) < 8 + length:
#                         break

#                     frame = buffer[:8 + length]
#                     del buffer[:8 + length]
#                     payload = frame[8:]

#                     if msg_id == 0x0001:
#                         client_socket.sendall(self.HEARTBEAT_ACK)
#                         continue

#                     if msg_id == 0x1002:
#                         obj = json.loads(
#                             binascii.unhexlify(payload.hex())
#                             .decode(errors="ignore")
#                             .strip("\x00")
#                         )
#                         dn, ss, ch = obj.get("dn"), obj.get("ss"), obj.get("ch")
#                         print(f"[VIDEO REQUEST] DN={dn} SS={ss} CH={ch}")
#                         client_socket.sendall(self.build_4002_ack(payload))
#                         continue

#                     if msg_id == 0x0011:
#                         media_data = payload[12:]

#                         if len(media_data) > 100:
#                             is_media_stream = True

#                         if not (dn and ss and ch and is_media_stream):
#                             continue

#                         if not started:
#                             print(f"[DOWNLOAD STARTED] DN={dn} SS={ss} CH={ch}")
#                             self.update_video_request_status(ss, dn, 4, None, None)
#                             self.start_ffmpeg_writer(dn, ss, ch)
#                             started = True

#                         self.FFMPEG_PROCS[(dn, ss, ch)].stdin.write(media_data)

#         finally:
#             client_socket.close()
#             self.ACTIVE_CONNECTIONS -= 1
#             print(f"[CONNECTION CLOSED] #{conn_id}")

#             if dn and ss and ch:
#                 self.stop_ffmpeg_writer(dn, ss, ch)

#     # ---------------------------------------------------------
#     # SERVER START
#     # ---------------------------------------------------------
#     def start_server(self):

#         print(f"[SERVER] Listening on port {self.port}")
#         executor = ThreadPoolExecutor(max_workers=self.max_workers)

#         server_socket = socket.socket()
#         server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#         server_socket.bind(("0.0.0.0", self.port))
#         server_socket.listen(50)

#         while True:
#             client_socket, addr = server_socket.accept()
#             self.TOTAL_CONNECTIONS += 1
#             executor.submit(
#                 self.handle_client,
#                 client_socket,
#                 addr,
#                 self.TOTAL_CONNECTIONS
#             )


# if __name__ == "__main__":
#     MDVRVideoRequestHandler("config.ini").start_server()




import socket
import struct
import json
import binascii
import subprocess
import os
import configparser
import pyodbc
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from logger import Logger


class MDVRVideoRequestHandler:

    MAGIC = b"\x48\x01"
    HEARTBEAT_ACK = b"\x48\x01\x01\x40\x00\x00\x00\x00"

    def __init__(self, config_file="config.ini"):

        self.config = configparser.ConfigParser()
        self.config.read(config_file)

        self.logger = Logger(config_file)

        # ---------------- CONFIG ----------------
        self.port = int(self.config["SERVER"]["port"])
        self.max_workers = int(self.config["SERVER"]["max_workers"])
        self.ffmpeg_path = self.config["FFMPEG"]["binary_path"]

        self.video_base_dir = os.path.normpath(
            self.config["Video"]["VideoBaseDirectory"]
        )

        self.db_str = self.config["DATABASE"]["connection_str"]
        self.update_sp = self.config["DATABASE"]["update_video_req_sp"]

        # ---------------- STATE ----------------
        self.ACTIVE_CONNECTIONS = 0
        self.TOTAL_CONNECTIONS = 0
        self.FFMPEG_PROCS = {}

        # ---------------- INIT ----------------
        os.makedirs(self.video_base_dir, exist_ok=True)

        print(f"[CONFIG] Port={self.port} Workers={self.max_workers}")
        print(f"[CONFIG] VideoBaseDir={self.video_base_dir}")
        self.logger.info(f"[CONFIG] VideoBaseDir={self.video_base_dir}")

    # ---------------------------------------------------------
    # PATH HELPERS (CONFIG DRIVEN)
    # ---------------------------------------------------------
    def get_video_directory(self, dn, ch):
        today = datetime.now().strftime("%Y-%m-%d")

        path = os.path.join(
            self.video_base_dir,
            today,
            str(dn),
            str(ch)
        )

        os.makedirs(path, exist_ok=True)
        return path

    def get_video_file_path(self, dn, ss, ch):
        folder = self.get_video_directory(dn, ch)
        filename = f"{dn}_{ss}_{ch}.mp4"
        return os.path.join(folder, filename)

    # ---------------------------------------------------------
    # BUILD 4002 ACK
    # ---------------------------------------------------------
    def build_4002_ack(self, payload):
        return (
            b"\x48\x01" +
            struct.pack("<H", 0x4002) +
            struct.pack("<I", len(payload)) +
            payload
        )

    # ---------------------------------------------------------
    # STORED PROCEDURE UPDATE
    # ---------------------------------------------------------
    def update_video_request_status(self, ss, dn, status, file_name=None, file_path=None):

        sql = f"{{CALL {self.update_sp} (?,?,?,?,?)}}"
        conn = None

        try:
            conn = pyodbc.connect(self.db_str, timeout=5)
            conn.autocommit = False
            cur = conn.cursor()

            cur.execute(
                sql,
                str(ss),
                int(dn),
                int(status),
                file_name,
                file_path
            )
            conn.commit()

            self.logger.info(
                f"[DB UPDATE] DN={dn} SS={ss} STATUS={status}"
            )

        except Exception as e:
            self.logger.error(f"[DB ERROR] {e}")

        finally:
            if conn:
                conn.close()

    # ---------------------------------------------------------
    # START FFMPEG
    # ---------------------------------------------------------
    def start_ffmpeg_writer(self, dn, ss, ch):

        output_file = self.get_video_file_path(dn, ss, ch)

        print(f"[FFMPEG START] {output_file}")
        self.logger.info(f"[FFMPEG START] {output_file}")

        cmd = [
            self.ffmpeg_path, "-y",
            "-loglevel", "error",
            "-f", "h264",
            "-i", "pipe:0",
            "-c", "copy",
            "-movflags", "+faststart",
            output_file
        ]

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        self.FFMPEG_PROCS[(dn, ss, ch)] = proc

    # ---------------------------------------------------------
    # STOP FFMPEG
    # ---------------------------------------------------------
    def stop_ffmpeg_writer(self, dn, ss, ch):

        key = (dn, ss, ch)
        if key not in self.FFMPEG_PROCS:
            return

        proc = self.FFMPEG_PROCS[key]
        file_name = f"{dn}_{ss}_{ch}.mp4"
        file_path = self.get_video_directory(dn, ch)

        try:
            proc.stdin.close()
            proc.wait(timeout=5)

            full_path = os.path.join(file_path, file_name).replace("\\", "/")

            print(f"[DOWNLOAD COMPLETED] {full_path}")
            self.logger.info(f"[DOWNLOAD COMPLETED] {full_path}")

            self.update_video_request_status(
                ss, dn, 6,
                file_name=file_name,
                file_path=full_path
            )

        except Exception as e:
            self.logger.error(f"[DOWNLOAD FAILED] DN={dn} SS={ss} ERR={e}")
            self.update_video_request_status(ss, dn, 5, None, None)

        del self.FFMPEG_PROCS[key]

    # ---------------------------------------------------------
    # CLIENT HANDLER
    # ---------------------------------------------------------
    def handle_client(self, client_socket, addr, conn_id):

        self.ACTIVE_CONNECTIONS += 1
        self.logger.info(f"[NEW CONNECTION] #{conn_id} {addr}")

        buffer = bytearray()
        dn = ss = ch = None
        is_media_stream = False
        started = False

        try:
            while True:
                chunk = client_socket.recv(8192)
                if not chunk:
                    break

                buffer.extend(chunk)

                while True:

                    if len(buffer) < 8 or buffer[:2] != self.MAGIC:
                        break

                    msg_id = struct.unpack_from("<H", buffer, 2)[0]
                    length = struct.unpack_from("<I", buffer, 4)[0]

                    if len(buffer) < 8 + length:
                        break

                    frame = buffer[:8 + length]
                    del buffer[:8 + length]
                    payload = frame[8:]

                    if msg_id == 0x0001:
                        client_socket.sendall(self.HEARTBEAT_ACK)
                        continue

                    if msg_id == 0x1002:
                        obj = json.loads(
                            binascii.unhexlify(payload.hex())
                            .decode(errors="ignore")
                            .strip("\x00")
                        )
                        dn, ss, ch = obj.get("dn"), obj.get("ss"), obj.get("ch")
                        self.logger.info(f"[VIDEO REQUEST] DN={dn} SS={ss} CH={ch}")
                        client_socket.sendall(self.build_4002_ack(payload))
                        continue

                    if msg_id == 0x0011:
                        media_data = payload[12:]

                        if len(media_data) > 100:
                            is_media_stream = True

                        if not (dn and ss and ch and is_media_stream):
                            continue

                        if not started:
                            self.logger.info(f"[DOWNLOAD STARTED] DN={dn} SS={ss}")
                            self.update_video_request_status(ss, dn, 4, None, None)
                            self.start_ffmpeg_writer(dn, ss, ch)
                            started = True

                        self.FFMPEG_PROCS[(dn, ss, ch)].stdin.write(media_data)

        finally:
            client_socket.close()
            self.ACTIVE_CONNECTIONS -= 1
            self.logger.info(f"[CONNECTION CLOSED] #{conn_id}")

            if dn and ss and ch:
                self.stop_ffmpeg_writer(dn, ss, ch)

    # ---------------------------------------------------------
    # SERVER START
    # ---------------------------------------------------------
    def start_server(self):

        print(f"[SERVER] Listening on port {self.port}")
        executor = ThreadPoolExecutor(max_workers=self.max_workers)

        server_socket = socket.socket()
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", self.port))
        server_socket.listen(50)

        while True:
            client_socket, addr = server_socket.accept()
            self.TOTAL_CONNECTIONS += 1
            executor.submit(
                self.handle_client,
                client_socket,
                addr,
                self.TOTAL_CONNECTIONS
            )


if __name__ == "__main__":
    MDVRVideoRequestHandler("config.ini").start_server()
