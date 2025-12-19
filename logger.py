import os
from datetime import datetime
import configparser


class Logger:

    def __init__(self, config_file_path="config.ini"):
        self.config = self.load_config(config_file_path)

        # Base directories from config
        self.base_log_dir = self.config.get("Logging", "LogDirectory")
        self.base_error_dir = self.config.get("Logging", "LogDirectory_Error")

        # Ensure root folders exist
        os.makedirs(self.base_log_dir, exist_ok=True)
        os.makedirs(self.base_error_dir, exist_ok=True)

        self.current_date_folder = None
        self.update_date_folder()

    # ----------------------------------------------------------------
    def load_config(self, config_file_path):
        config = configparser.ConfigParser()
        config.read(config_file_path)
        return config

    # ----------------------------------------------------------------
    def update_date_folder(self):
        today = datetime.now().strftime("%Y-%m-%d")

        if self.current_date_folder != today:
            self.current_date_folder = today

            self.today_log_dir = os.path.join(self.base_log_dir, today)
            self.today_error_dir = os.path.join(self.base_error_dir, today)

            os.makedirs(self.today_log_dir, exist_ok=True)
            os.makedirs(self.today_error_dir, exist_ok=True)

    # ----------------------------------------------------------------
    def _write(self, file_path, message):
        try:
            with open(file_path, "a", encoding="utf-8") as f:
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"{now} ==> {message}\n")
        except Exception as e:
            print(f"[LOGGER ERROR] {e}")


    # ----------------------------------------------------------------
    # REQUIRED BY MDVR HANDLER
    def info(self, message):
        self.update_date_folder()
        logfile = os.path.join(self.today_log_dir, "Info.log")
        self._write(logfile, message)

    # ----------------------------------------------------------------
    # REQUIRED BY MDVR HANDLER
    def error(self, message):
        self.update_date_folder()
        logfile = os.path.join(self.today_error_dir, "Error.log")
        self._write(logfile, message)

    # ----------------------------------------------------------------
    def log(self, log_type, message):
        self.update_date_folder()
        logfile = os.path.join(self.today_log_dir, f"{log_type}.log")
        self._write(logfile, message)

    # ----------------------------------------------------------------
    def get_video_folder(self, device_no, channel_no):
        today = datetime.now().strftime("%Y-%m-%d")

        video_base_dir = os.path.normpath(
            self.config.get("Video", "VideoBaseDirectory")
        )

        path = os.path.join(
            video_base_dir,
            today,
            str(device_no),
            str(channel_no)
        )

        os.makedirs(path, exist_ok=True)
        return path


    # ----------------------------------------------------------------
    def get_error_folder(self, device_no, channel_no):
        self.update_date_folder()

        path = os.path.join(
            self.today_error_dir,
            str(device_no),
            str(channel_no),
            "error"
        )
        os.makedirs(path, exist_ok=True)
        return path


# -----------------------------------------------------
if __name__ == "__main__":
    logger = Logger()
    logger.info("Server started")
    logger.error("Test error message")
