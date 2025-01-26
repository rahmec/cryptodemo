import sys
from PyQt5.QtWidgets import QApplication
from views.homeView import HomeView 

if __name__ == '__main__':
    app = QApplication(sys.argv)
    home_view = HomeView()
    home_view.show()
    sys.exit(app.exec_())
