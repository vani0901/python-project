import sys
import time
import subprocess
from PyQt5.QtCore import QUrl, Qt  # Import Qt from PyQt5.QtCore
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget
from PyQt5.QtWebEngineWidgets import QWebEngineView

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("crsss")
        self.setGeometry(100, 100, 1536, 864)  # Adjusted geometry values

        # Disable maximize button
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowMaximizeButtonHint)

        self.browser = QWebEngineView()
        self.load_flask_app()  # Method to load Flask app

        layout = QVBoxLayout()
        layout.addWidget(self.browser)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def load_flask_app(self):
        # Wait for Flask app to start (adjust sleep time as needed)
        time.sleep(2)
        self.browser.setUrl(QUrl("http://127.0.0.1:5000"))

if __name__ == '__main__':
    app = QApplication(sys.argv)

    # Start Flask app
    flask_process = subprocess.Popen(['python', 'app.py'])

    window = MainWindow()
    window.show()

    # Close Flask app when PyQt5 application is closed
    sys.exit(app.exec_())
    flask_process.terminate()
