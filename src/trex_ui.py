from PyQt5 import QtWidgets, QtCore, QtGui
import pyqtgraph
import pickle
import time
import splitter
import logging

class Gui(QtWidgets.QMainWindow):

    def __init__(self):
        super().__init__()
        self.ui_log = logging.getLogger("trex.ui")

    def closeEvent(self, event):
        self.save_state()
        event.accept()

    def draw_window(self):
        # Define window's geometry, title and the icon
        self.set_window_view()

        # Create a link window's menu items
        self.set_window_menu()

        # Place and order window's widgets and elements
        self.set_window_layout()

        # Create control panel
        self.set_control_panel()

        self.restore_state()
        self.show()

    def set_window_view(self):
        self.setMinimumWidth(1000)
        self.setMinimumHeight(700)
        self.setGeometry(100,100,1000,700)
        self.setWindowTitle("Trex")
        self.setWindowIcon(QtGui.QIcon("img/icon.png"))

        self.status = QtWidgets.QStatusBar()
        self.setStatusBar(self.status)

    def set_window_menu(self):
        self.menu = self.menuBar()

        #self.menuSever = self.menu.addMenu("Server")
        self.menuProfile = self.menu.addMenu("Profile")
        self.menuGraph = self.menu.addMenu("Graphs")
        self.menuHelp = self.menu.addMenu("Help")

        #self.newServer = QtWidgets.QAction("Configure new server")
        #self.newServer.triggered.connect(self.new_server)
        #self.menuSever.addAction(self.newServer)

        self.newProfile = QtWidgets.QAction("New traffic profile")
        self.newProfile.triggered.connect(self.new_profile)
        self.menuProfile.addAction(self.newProfile)

        self.editProfile = QtWidgets.QAction("Edit traffic profile")
        self.editProfile.triggered.connect(self.edit_profile)
        self.menuProfile.addAction(self.editProfile)

        self.addGraph = QtWidgets.QAction("New graph")
        self.addGraph.triggered.connect(self.add_graph)
        self.menuGraph.addAction(self.addGraph)

        self.aboutMenu = QtWidgets.QAction("About")
        self.aboutMenu.triggered.connect(self.about)
        self.menuHelp.addAction(self.aboutMenu)

    def set_window_layout(self):
        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)

        self.left_widget = QtWidgets.QWidget()
        self.left_widget.setMinimumWidth(410)

        graph_view = QtWidgets.QWidget(self)
        graph_view_container = QtWidgets.QWidget()
        self.graph_list = QtWidgets.QVBoxLayout(graph_view)
        self.graph_list.setContentsMargins(5, 5, 5, 5)
        self.graph_list.setAlignment(QtCore.Qt.AlignTop)
        graph_view_container.setLayout(self.graph_list)

        graph_scroll = QtWidgets.QScrollArea()
        graph_scroll.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        graph_scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        graph_scroll.setWidgetResizable(True)
        graph_scroll.setWidget(graph_view_container)

        graph_view_layout = QtWidgets.QVBoxLayout(graph_view)
        graph_view_layout.setContentsMargins(0, 0, 0, 0)
        graph_view_layout.addWidget(graph_scroll)
        graph_view.setLayout(graph_view_layout)

        self.splitter = QtWidgets.QSplitter()
        self.splitter.setHandleWidth(10)
        self.splitter.setStyleSheet(" QSplitter::handle { image: url(img/handle.png); } ")
        self.splitter.setOpaqueResize(False)
        self.splitter.addWidget(self.left_widget)
        self.splitter.addWidget(graph_view)
        self.splitter.setStretchFactor(1,1)
        self.splitter.setSizes([410,580])

        self.main_layout = QtWidgets.QHBoxLayout(self.central_widget)
        self.main_layout.setSpacing(0)
        self.main_layout.setContentsMargins(5, 5, 5, 5)
        self.main_layout.addWidget(self.splitter)

        self.left_layout = QtWidgets.QVBoxLayout(self.left_widget)
        self.left_layout.setSpacing(5)
        self.left_layout.setContentsMargins(0, 0, 0, 0)
        self.exec_prop = QtWidgets.QWidget()
        self.exec_prop.setFixedHeight(320)
        #self.exec_prop.setStyleSheet("border: 1px solid red")
        self.exec_details = QtWidgets.QLabel()
        #self.exec_details.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
        #with open("stat_template.html", "r") as f:
        #    self.exec_details.setText("".join(f.readlines()))
        #self.exec_details.setStyleSheet("border: 1px solid red")
        self.left_layout.addWidget(self.exec_prop)
        self.left_layout.addWidget(self.exec_details)

    def set_control_panel(self):
        labels = []
        label_pos = 5
        for label in ["T-Rex IP address", "Traffic file path", "Test duration", 
                      "Rate multiplier", "NAT Support", "IPv6"]:
            labels.append(QtWidgets.QLabel(self.exec_prop))
            labels[-1].setText(label)
            labels[-1].setGeometry(10, label_pos, 90, 20)
            label_pos += 25

        self.srv_ip = QtWidgets.QLineEdit(self.exec_prop)
        self.srv_ip.setGeometry(100, 5, 150, 20)

        self.check_button = QtWidgets.QPushButton(self.exec_prop)
        self.check_button.setText("Check")
        self.check_button.setGeometry(255, 3, 75, 23)

        self.config_button = QtWidgets.QPushButton(self.exec_prop)
        self.config_button.setText("Settings")
        self.config_button.setGeometry(335, 3, 75, 23)
        self.config_button.setEnabled(False)

        self.path = QtWidgets.QLineEdit(self.exec_prop)
        self.path.setGeometry(100, 30, 230, 20)

        self.open_button = QtWidgets.QPushButton(self.exec_prop)
        self.open_button.setText("Open")
        self.open_button.setGeometry(335, 29, 75, 23)

        self.duration = QtWidgets.QSpinBox(self.exec_prop)
        self.duration.setMinimum(30)
        self.duration.setMaximum(9999999)
        self.duration.setGeometry(100, 55, 150, 20)

        self.rate = QtWidgets.QSpinBox(self.exec_prop)
        self.rate.setMinimum(1)
        self.rate.setMaximum(9999999)
        self.rate.setGeometry(100, 80, 150, 20)

        self.nat = QtWidgets.QCheckBox(self.exec_prop)
        self.nat.setGeometry(100, 105, 20, 20)

        self.ipv6 = QtWidgets.QCheckBox(self.exec_prop)
        self.ipv6.setGeometry(100, 130, 20, 20)

        self.client_box = QtWidgets.QGroupBox(self.exec_prop)
        self.client_box.setTitle("Port 0 - Client side")
        self.client_box.setGeometry(0, 155, 410, 65)

        self.server_box = QtWidgets.QGroupBox(self.exec_prop)
        self.server_box.setTitle("Port 1 - Server side")
        self.server_box.setGeometry(0, 220, 410, 65)

        for box in [self.client_box, self.server_box]:
            ip_addr = QtWidgets.QLabel(box)
            ip_addr.setText("IP address")
            ip_addr.setGeometry(10, 15, 60, 20)
            box.ip = QtWidgets.QLineEdit(box)
            box.ip.setGeometry(75, 15, 120, 20)
            next_hop = QtWidgets.QLabel(box)
            next_hop.setText("Next hop")
            next_hop.setGeometry(210, 15, 60, 20)
            box.next_hop = QtWidgets.QLineEdit(box)
            box.next_hop.setGeometry(275, 15, 120, 20)
            vlan_id = QtWidgets.QLabel(box)
            vlan_id.setText("VLAN ID")
            vlan_id.setGeometry(10, 40, 60, 20)
            box.vlan = QtWidgets.QLineEdit(box)
            box.vlan.setGeometry (75, 40, 60, 20)

        self.start_button = QtWidgets.QPushButton(self.exec_prop)
        self.start_button.setGeometry(255, 295, 75, 23)
        self.start_button.setText("Start")

        self.stop_button = QtWidgets.QPushButton(self.exec_prop)
        self.stop_button.setGeometry(335, 295, 75, 23)
        self.stop_button.setText("Stop")
        self.lock_button()

    def lock_button(self):
        self.stop_button.setEnabled(False)
        self.start_button.setEnabled(True)

    def unlock_button(self):
        self.stop_button.setEnabled(True)
        self.start_button.setEnabled(False)

    def save_state(self):
        state = {}
        state["ip"] = self.srv_ip.text()
        state["path"] = self.path.text()
        state["duration"] = self.duration.value()
        state["rate"] = self.rate.value()
        state["nat"] = self.nat.isChecked()
        state["ipv6"] = self.ipv6.isChecked()
        state["client_ip"] = self.client_box.ip.text()
        state["client_next_hop"] = self.client_box.next_hop.text()
        state["client_vlan"] = self.client_box.vlan.text()
        state["server_ip"] = self.server_box.ip.text()
        state["server_next_hop"] = self.server_box.next_hop.text()
        state["server_vlan"] = self.server_box.vlan.text()
        with open("config", "wb") as f:
            pickle.dump(state, f)

    def restore_state(self):
        try:
            with open("config", "rb") as f:
                state = pickle.load(f)
            self.srv_ip.setText(state["ip"])
            self.path.setText(state["path"])
            self.duration.setValue(state["duration"])
            self.rate.setValue(state["rate"])
            self.nat.setChecked(state["nat"])
            self.ipv6.setChecked(state["ipv6"])
            self.client_box.ip.setText(state["client_ip"])
            self.client_box.next_hop.setText(state["client_next_hop"])
            self.client_box.vlan.setText(state["client_vlan"])
            self.server_box.ip.setText(state["server_ip"])
            self.server_box.next_hop.setText(state["server_next_hop"])
            self.server_box.vlan.setText(state["server_vlan"])
        except:
            pass

    def new_server(self):
        pass

    def new_profile(self):
        pass

    def edit_profile(self):
        pass

    def add_graph(self):
        pass

    def about(self):
        AboutDialog(self)

class Dialog(QtWidgets.QDialog):

    def __init__(self, parent_object: QtWidgets.QMainWindow, width: int, height: int, title: str):
        super().__init__(parent_object)
        main_window_size = parent_object.geometry()
        x = main_window_size.x() + (main_window_size.width() - width) // 2
        y = main_window_size.y() + (main_window_size.height() - height) // 2
        self.setGeometry(x, y, width, height)
        self.setFixedSize(width, height)
        self.setWindowIcon(QtGui.QIcon("img/icon.png"))
        self.setWindowTitle(title)
        self.main_window = parent_object


class FileOpenDialog(Dialog):

    def __init__(self, parent_object):
        
        super().__init__(parent_object, 640, 480, "Open file")
        
        self.file_tree = QtWidgets.QTreeWidget(self)
        self.file_tree.setGeometry(10, 10, 620, 427)
        self.file_tree.setColumnCount(1)
        self.file_tree.setHeaderHidden(True)
        self.file_tree.itemExpanded.connect(self._set_column_width)
        self.file_tree.itemCollapsed.connect(self._set_column_width)
        self.file_tree.itemDoubleClicked.connect(self.open_file)
        
        self.open_button = QtWidgets.QPushButton(self)
        self.open_button.setGeometry(470, 447, 75, 23)
        self.open_button.setText("Open")
        self.open_button.clicked.connect(self.open_file)
        
        self.cancel_button = QtWidgets.QPushButton(self)
        self.cancel_button.setText("Cancel")
        self.cancel_button.setGeometry(555, 447, 75, 23)
        self.cancel_button.clicked.connect(self.close)
        
        self.show()

    def _set_column_width(self):
        self.file_tree.resizeColumnToContents(0)

    def open_file(self):
        file_name = self.file_tree.currentItem().text(0)
        path = self.file_tree.currentItem().path
        if not file_name.endswith(self.ext):
            return

        self.file = f"{path}{file_name}"
        self.accept()        

    def fill_tree(self, data, ext):
        self.ext = ext
        for element in data.keys():
            if element == ".":
                continue
            folder_item = QtWidgets.QTreeWidgetItem([element])
            folder_item.path = f"{element}/"
            self.file_tree.addTopLevelItem(folder_item)
            self.nested_tree_elements(data[element], folder_item)
        if "." in data.keys():
            for file_element in data["."]:
                    file_item = QtWidgets.QTreeWidgetItem([file_element])
                    file_item.path = ""
                    self.file_tree.addTopLevelItem(file_item)

    def nested_tree_elements(self, data, container_element):
        for element in data.keys():
            if element == ".":
                continue
            folder_item = QtWidgets.QTreeWidgetItem([element])
            folder_item.path = f"{container_element.path}{element}/"
            container_element.addChild(folder_item)
            self.nested_tree_elements(data[element], folder_item)
        if "." in data.keys():
            for file_element in data["."]:
                file_item = QtWidgets.QTreeWidgetItem([file_element])
                file_item.path = container_element.path
                container_element.addChild(file_item)

class AboutDialog(Dialog):

    def __init__(self, parent_object):
        
        super().__init__(parent_object, 450, 250, "About")
        pic = QtWidgets.QLabel(self)
        pic.setGeometry(0, 20, 450, 165)
        picture = QtGui.QPixmap("img/trex_logo.png")
        pic.setPixmap(picture.scaled(450,165))
        version = QtWidgets.QLabel(self)
        version.setGeometry(150, 200, 450, 50)
        version.setText("<h1>TRex GUI v0.1</h1>")
        self.show()

class ServerSettingsDialog(Dialog):

    def __init__(self, parent_object):
        
        super().__init__(parent_object, 250, 155, "Server settings")
        self.show()


class AuthDialog(Dialog):

    def __init__(self, parent_object):
        
        super().__init__(parent_object, 250, 155, "About")
        info_label = QtWidgets.QLabel(self)
        info_label.setGeometry(10, 5, 220, 40)
        info_label.setText("Operation requires SSH access to the server.\nPlease, provide credentials.")
        ip_addr_label = QtWidgets.QLabel(self)
        ip_addr_label.setGeometry(10, 50, 70, 20)
        ip_addr_label.setText("IP address")
        self.ip_addr = QtWidgets.QLineEdit(self)
        self.ip_addr.setGeometry(80, 50, 160, 20)
        user_label = QtWidgets.QLabel(self)
        user_label.setGeometry(10, 75, 70, 20)
        user_label.setText("User")
        self.user = QtWidgets.QLineEdit(self)
        self.user.setGeometry(80, 75, 160, 20)
        password_label = QtWidgets.QLabel(self)
        password_label.setGeometry(10, 100, 70, 20)
        password_label.setText("Password")
        self.password = QtWidgets.QLineEdit(self)
        self.password.setGeometry(80, 100, 160, 20)
        self.password.setEchoMode(2)
        submit = QtWidgets.QPushButton(self)
        submit.setGeometry(165, 125, 75, 23)
        submit.setText("Ok")
        submit.clicked.connect(self.submit)
        self.show()

    def submit(self):
        self.credentials = [self.ip_addr.text(), self.user.text(), self.password.text()]
        self.accept()

class ProfileDialog(Dialog):

    def __init__(self, parent_object):
        super().__init__(parent_object, 550, 470, "Profile Editor")

        name_label = QtWidgets.QLabel(self)
        name_label.setGeometry(5, 10, 90, 20)
        name_label.setText("Filename")

        self.name = QtWidgets.QLineEdit(self)
        self.name.setGeometry(100, 10, 150, 20)

        self.load_profile = QtWidgets.QPushButton(self)
        self.load_profile.setGeometry(260, 8, 85, 23)
        self.load_profile.setText("Load")

        cstart_label = QtWidgets.QLabel(self)
        cstart_label.setGeometry(5, 35, 90, 20)
        cstart_label.setText("Client start IP")

        self.cstart = QtWidgets.QLineEdit(self)
        self.cstart.setGeometry(100, 35, 100, 20)

        cend_label = QtWidgets.QLabel(self)
        cend_label.setGeometry(250, 35, 90, 20)
        cend_label.setText("Client end IP")

        self.cend = QtWidgets.QLineEdit(self)
        self.cend.setGeometry(345, 35, 100, 20)

        sstart_label = QtWidgets.QLabel(self)
        sstart_label.setGeometry(5, 60, 90, 20)
        sstart_label.setText("Server start IP")

        self.sstart = QtWidgets.QLineEdit(self)
        self.sstart.setGeometry(100, 60, 100, 20)

        send_label = QtWidgets.QLabel(self)
        send_label.setGeometry(250, 60, 90, 20)
        send_label.setText("Server end IP")

        self.send = QtWidgets.QLineEdit(self)
        self.send.setGeometry(345, 60, 100, 20)

        sipv6_label = QtWidgets.QLabel(self)
        sipv6_label.setText("Client IPv6 prefix")
        sipv6_label.setGeometry(5, 85, 90, 20)

        self.sipv6 = QtWidgets.QLineEdit(self)
        self.sipv6.setGeometry(100, 85, 180, 20)

        dipv6_label = QtWidgets.QLabel(self)
        dipv6_label.setText("Server IPv6 prefix")
        dipv6_label.setGeometry(5, 110, 90, 20)

        self.dipv6 = QtWidgets.QLineEdit(self)
        self.dipv6.setGeometry(100, 110, 180, 20)

        ipg_label = QtWidgets.QLabel(self)
        ipg_label.setGeometry(5, 135, 90, 20)
        ipg_label.setText("Override IPG")

        self.ipg = QtWidgets.QCheckBox(self)
        self.ipg.setGeometry(100, 135, 20, 20)

        self.upload_pcap = QtWidgets.QPushButton(self)
        self.upload_pcap.setGeometry(455, 8, 90, 23)
        self.upload_pcap.setText("Upload PCAP")

        self.split_pcap = QtWidgets.QPushButton(self)
        self.split_pcap.setGeometry(455, 33, 90, 23)
        self.split_pcap.setText("Split PCAP")

        self.add_pcap = QtWidgets.QPushButton(self)
        self.add_pcap.setGeometry(455, 58, 90, 23)
        self.add_pcap.setText("Add PCAP")

        self.save_profile = QtWidgets.QPushButton(self)
        self.save_profile.setGeometry(455, 83, 90, 23)
        self.save_profile.setText("Save")

        pcap_view = QtWidgets.QWidget(self)
        pcap_view.setGeometry(5, 160, 540, 305)

        pcap_view_container = QtWidgets.QWidget()
        self.pcap_list = QtWidgets.QVBoxLayout(pcap_view)
        self.pcap_list.setContentsMargins(5, 5, 5, 5)
        self.pcap_list.setAlignment(QtCore.Qt.AlignTop)
        pcap_view_container.setLayout(self.pcap_list)

        scroll = QtWidgets.QScrollArea()
        scroll.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        scroll.setWidgetResizable(True)
        scroll.setWidget(pcap_view_container)

        pcap_view_layout = QtWidgets.QVBoxLayout(pcap_view)
        pcap_view_layout.setContentsMargins(0, 0, 0, 0)
        pcap_view_layout.addWidget(scroll)
        pcap_view.setLayout(pcap_view_layout)

        self.show()

class SessionListDialog(Dialog):

    def __init__(self, parent_object):
        super().__init__(parent_object, 650, 480, "Valid sessions")
        self.table = QtWidgets.QTableWidget(self)
        self.table.setGeometry(5, 30, 640, 410)
        self.table.setColumnCount(10)
        self.table.setColumnHidden(0, True)
        self.table.setHorizontalHeaderLabels(["Tuple",
                                              " ",
                                              "Src IP",
                                              "Src Port",
                                              "Dst IP",
                                              "Dst Port",
                                              "Protocol",
                                              "Packets",
                                              "Packet Size",
                                              "Payload Size"])
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.horizontalHeader().setSortIndicatorShown(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        self.table.resizeColumnsToContents()

        self.select_button = QtWidgets.QPushButton(self)
        self.select_button.setText("Select all")
        self.select_button.setGeometry(5, 3, 75, 23)
        self.select_button.clicked.connect(self.seclect_all)

        self.unselect_button = QtWidgets.QPushButton(self)
        self.unselect_button.setText("Unselect all")
        self.unselect_button.setGeometry(85, 3, 75, 23)
        self.unselect_button.clicked.connect(self.unseclect_all)

        search = QtWidgets.QLabel(self)
        search.setText("Search")
        search.setGeometry(450, 5, 40, 20)

        self.search = QtWidgets.QLineEdit(self)
        self.search.setGeometry(495, 5, 150, 20)
        self.search.textChanged.connect(self.filter)

        self.split = QtWidgets.QPushButton(self)
        self.split.setText("Split")
        self.split.setGeometry(570, 448, 75, 23)
        self.split.clicked.connect(self.split_pcap)

        self.show()

    def filter(self):
        search_pattern = self.search.text()
        for i in range(self.table.rowCount()):
            if search_pattern in self.table.item(i, 2).text():
                self.table.showRow(i)
            elif search_pattern in self.table.item(i, 3).text():
                self.table.showRow(i)
            elif search_pattern in self.table.item(i, 4).text():
                self.table.showRow(i)
            elif search_pattern in self.table.item(i, 5).text():
                self.table.showRow(i)
            elif search_pattern in self.table.item(i, 6).text():
                self.table.showRow(i)
            else:
                self.table.hideRow(i)

    def new_row(self, session_tuple, session_details):
        protocol_map = {"00000006" : "TCP", "00000011" : "UDP"}
        row_count = self.table.rowCount()
        self.table.insertRow(row_count)
        self.table.setRowHeight(row_count, 20)
        
        src_ip = QtWidgets.QTableWidgetItem(splitter.hex_to_ipv4(session_tuple[0]))
        src_ip.setTextAlignment(132) # Horizontal - center, vertical - center
        src_port = QtWidgets.QTableWidgetItem(splitter.hex_to_port(session_tuple[1]))
        src_port.setTextAlignment(132)
        dst_ip = QtWidgets.QTableWidgetItem(splitter.hex_to_ipv4(session_tuple[2]))
        dst_ip.setTextAlignment(132)
        dst_port = QtWidgets.QTableWidgetItem(splitter.hex_to_port(session_tuple[3]))
        dst_port.setTextAlignment(132)
        protocol = QtWidgets.QTableWidgetItem(protocol_map[session_tuple[4]])
        protocol.setTextAlignment(132)
        packet_counter = QtWidgets.QTableWidgetItem(str(session_details[7]))
        packet_counter.setTextAlignment(132)
        packets_size = QtWidgets.QTableWidgetItem(str(session_details[6]))
        packets_size.setTextAlignment(132)
        payload_size = QtWidgets.QTableWidgetItem(str(session_details[8]))
        payload_size.setTextAlignment(132)
        checkbox_widget = QtWidgets.QWidget()
        checkbox = QtWidgets.QCheckBox()
        checkbox_layout = QtWidgets.QHBoxLayout(checkbox_widget)
        checkbox_layout.addWidget(checkbox)
        checkbox_layout.setAlignment(QtCore.Qt.AlignCenter)
        checkbox_layout.setContentsMargins(0, 0, 0, 0)

        self.table.setItem(row_count, 0, QtWidgets.QTableWidgetItem(":".join(session_tuple)))
        self.table.setCellWidget(row_count, 1, checkbox_widget)
        self.table.setItem(row_count, 2, src_ip)
        self.table.setItem(row_count, 3, src_port)
        self.table.setItem(row_count, 4, dst_ip)
        self.table.setItem(row_count, 5, dst_port)
        self.table.setItem(row_count, 6, protocol)
        self.table.setItem(row_count, 7, packet_counter)
        self.table.setItem(row_count, 8, packets_size)
        self.table.setItem(row_count, 9, payload_size)

        self.table.resizeColumnsToContents()

    def configure_sorting(self):
        self.table.setSortingEnabled(True)

    def seclect_all(self):
        for i in range(self.table.rowCount()):
            self.table.cellWidget(i, 1).layout().itemAt(0).widget().setChecked(True)

    def unseclect_all(self):
        for i in range(self.table.rowCount()):
            self.table.cellWidget(i, 1).layout().itemAt(0).widget().setChecked(False)

    def split_pcap(self):
        self.session_list = []
        for i in range(self.table.rowCount()):
            if not self.table.cellWidget(i, 1).layout().itemAt(0).widget().isChecked():
                continue
            self.session_list.append(tuple(self.table.item(i, 0).text().split(":")))
        self.accept()


class ProgressDialog(Dialog):

    def __init__(self, parent_object):
        super().__init__(parent_object, 400, 40, "Progress")
        self.progress_bar = QtWidgets.QProgressBar(self)
        self.progress_bar.setGeometry(20, 10, 360, 20)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.show()


class ChoseGraphDialog(Dialog):

    def __init__(self, parent_object, graph_options):
        super().__init__(parent_object, 260, 60, "Create new graph")
        
        type_label = QtWidgets.QLabel(self)
        type_label.setGeometry(5, 10, 75, 20)
        type_label.setText("Graph type")

        self.type_box = QtWidgets.QComboBox(self)
        self.type_box.setGeometry(85, 10, 170, 20)
        self.type_box.addItems(graph_options)

        ok_button = QtWidgets.QPushButton(self)
        ok_button.setGeometry(180, 32, 75, 23)
        ok_button.setText("OK")
        ok_button.clicked.connect(self.chosen)

        self.show()

    def chosen(self):
        self.value = self.type_box.currentText()
        self.accept()


class PcapGroupBox(QtWidgets.QGroupBox):

    to_close = QtCore.pyqtSignal(object)

    def __init__(self, title, parent_object = None):
        super().__init__(parent_object)
        self.setFixedHeight(75)
        cps_label = QtWidgets.QLabel(self)
        cps_label.setGeometry(5, 20, 120, 20)
        cps_label.setText("Connections per second")

        self.cps = QtWidgets.QLineEdit(self)
        self.cps.setGeometry(130, 20, 120, 20)
        self.cps.setText("1")

        w_label = QtWidgets.QLabel(self)
        w_label.setGeometry(290, 20, 30, 20)
        w_label.setText("W")

        self.w = QtWidgets.QLineEdit(self)
        self.w.setGeometry(330, 20, 120, 20)
        self.w.setText("1")

        limit_label = QtWidgets.QLabel(self)
        limit_label.setGeometry(5, 45, 120, 20)
        limit_label.setText("Connection limit")

        self.limit = QtWidgets.QLineEdit(self)
        self.limit.setGeometry(130, 45, 120, 20)

        ipg_label = QtWidgets.QLabel(self)
        ipg_label.setGeometry(290, 45, 30, 20)
        ipg_label.setText("IPG")

        self.ipg = QtWidgets.QLineEdit(self)
        self.ipg.setGeometry(330, 45, 120, 20)
        self.ipg.setText("10000")

        self.close_btn = QtWidgets.QToolButton(self)
        self.close_btn.setGeometry(489, -1, 16, 16)
        icon = QtGui.QIcon("img/cross.png")
        self.close_btn.setIcon(icon)
        self.close_btn.clicked.connect(self.close_pressed)

        self.setTitle(title)
    
    def close_pressed(self):
        self.to_close.emit(self)

class GraphGroupBox(QtWidgets.QGroupBox):

    to_close = QtCore.pyqtSignal(object)

    def __init__(self, title, options, parent_object = None):
        super().__init__(parent_object)
        self.setFixedHeight(300)
        self.setTitle(title)
        self.graph_query = options[0]
        
        self.close_btn = QtWidgets.QToolButton(self)
        self.close_btn.setGeometry(520, -1, 16, 16)
        icon = QtGui.QIcon("img/cross.png")
        self.close_btn.setIcon(icon)
        self.close_btn.clicked.connect(self.close_pressed)

        self.graph = pyqtgraph.PlotWidget(parent=self, background=[255,255,255,255])
        self.graph.plotItem.showGrid(x=True, y=True)
        self.graph.setLabel("bottom", text="Seconds")
        self.graph.setLabel("left", text=options[1], units=options[2])
        self.graph.setMenuEnabled(enableMenu=False)
        layout = QtWidgets.QHBoxLayout()
        layout.addWidget(self.graph)
        self.setLayout(layout)

        self.plot = self.graph.getPlotItem().plot(pen="b")
        self.reset_plot()

    def reset_plot(self):
        self.data = [0]
        self.plot.setData(self.data)
        self.update_scale()
        self.plot_inited = False

    def update_plot(self, value):
        self.data.append(value)
        self.plot.setData(self.data)
        self.update_scale()

    def set_plot_init_data(self, value_list):
        self.data = value_list
        self.plot.setData(self.data)
        self.update_scale()
        self.plot_inited = True

    def update_scale(self):
        if not self.data:
            self.graph.setYRange(0, 1)
        else:
            self.graph.setYRange(min(self.data) - 1, max(self.data) + 1)
        x_visible_range = int((self.width() - 50) // 2)
        if len(self.data) < x_visible_range:
            self.graph.setXRange(0, x_visible_range)
        else:
            self.graph.setXRange(len(self.data) - x_visible_range, len(self.data))

    def resizeEvent(self, event):
        close_btn_pos = self.width() - 26
        self.close_btn.setGeometry(close_btn_pos, -1, 16, 16)
        self.update_scale()
        event.accept()
    
    def close_pressed(self):
        self.to_close.emit(self)
