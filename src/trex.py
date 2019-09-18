from PyQt5 import QtWidgets, QtCore, QtGui
from threading import Lock
from libs.trex_stf_lib.trex_client import CTRexClient, CTRexResult, CExceptionHandler
import libs.trex_stf_lib.trex_exceptions as trex_exceptions
import trex_ui
import splitter
import os
import pathlib
import sys
import json
import time
import logging
import logging.handlers

EXT_MODULES = ["libs/pyyaml-3.11/python3"]

for i in EXT_MODULES:
    sys.path.insert(1, i)

import yaml

TREX_TMP = "/tmp/trex_files"

class Window(trex_ui.Gui):

    def __init__(self):
        super().__init__()
        self.ui_log = logging.getLogger("trex.ui")
        self.draw_window()

        # Template for the trex server connection
        self.srv_con = None
        self.srv_ip.textChanged.connect(self.clear_connection)

        # Connect button signals
        self.check_button.clicked.connect(self.check_srv_status)
        self.config_button.clicked.connect(self.srv_settings)
        self.open_button.clicked.connect(self.open_yaml)
        self.start_button.clicked.connect(self.initiate)
        self.stop_button.clicked.connect(self.stop_traffic)

    def clear_connection(self):
        if self.srv_con:
            self.ui_log.info("IP address has been changed. Resetting connection to TRex server")
        self.srv_con = None

    def establish_connection(self):
        if not self.srv_con:
            try:
                self.ui_log.info("Verifying TRex master daemon status")
                self.srv_con = Client(self.srv_ip.text())
            except:
                QtWidgets.QMessageBox.warning(self, "Server is DOWN", "Trex is not running or server is down")
                self.ui_log.warning("TRex server is not responding")
                return False
        self.srv_status = self.srv_con.check_connection()
        if not self.srv_status["master_status"]:
            QtWidgets.QMessageBox.warning(self, "Server is DOWN", "Trex is not running or server is down")
            self.ui_log.warning("Master daemon is down")
            return False
        else:
            self.ui_log.info("Master daemon is running")
            return True

    def check_srv_status(self):
        if self.establish_connection():
            status_str = "Master daemon\tUP\n"
            self.ui_log.info("Verifying TRex daemon status")
            if self.srv_status["server_status"]:
                self.ui_log.info("TRex daemon is running")
                status_str += "Trex daemon\t\tUP\n"
                if self.srv_status["is_idle"]:
                    status_str += "Traffic\t\t\tIdle\n"
                else:
                    status_str += "Traffic\t\t\tGenerating\n"
                if self.srv_status["is_reserved"]:
                    status_str += "Reservation\t\tTaken\n"
                else:
                    status_str += "Reservation\t\tReleased\n"
            else:
                self.ui_log.warning("TRex daemon is down")
                status_str += "Trex daemon\t\tDOWN\n"
            QtWidgets.QMessageBox.information(self, "Trex status", status_str)

    def srv_settings(self):
        settings = trex_ui.ServerSettingsDialog(self)

    def open_yaml(self):
        ext = ".yaml"
        self.open_dialog = trex_ui.FileOpenDialog(self)
        self.ui_log.info("Trying to get list of YAML files")
        if self.establish_connection():
            if self.srv_status["server_status"]:
                yaml_tree = self.srv_con.get_file_tree(ext)
                self.open_dialog.fill_tree(yaml_tree, ext)
                if self.open_dialog.exec_():
                    self.path.setText(self.open_dialog.file)
            else:
                self.ui_log.warning("Failed to get list of YAML files")
                QtWidgets.QMessageBox.warning(self, "Error", "Can't get data from the server")

    def initiate(self):
        self.ui_log.info("Preparing for traffic generation")
        self.status.showMessage("Checking T-Rex status")
        if not self.establish_connection():
            return
        if self.srv_status["server_status"]:
            if not self.srv_status["is_idle"]:
                self.ui_log.warning("TRex is already running")
                self.status.showMessage("T-Rex is already running", msecs = 5000)
                button_pressed = QtWidgets.QMessageBox.question(self, "Trex status", 
                                     "Trex is already running. Do you want to monitor it?")
                if int(button_pressed) == 65536: # 16384 - Yes button; 65536 - No button
                    self.ui_log.warning("Traffic monitoring will not be started")
                    return
                self.ui_log.info("Traffic monitoring will be started")
            else:
                self.status.showMessage("Starting T-Rex")
                self.srv_con.restart_trex()
            exec_options = self.get_exec_options()
            self.monitoring_thread = TrexThread(self.srv_con, exec_options)
            self.monitoring_thread.start_error.connect(self.trex_start_error)
            self.results = Results()
            for graph_id in range(self.graph_list.count()):
                graph_box = self.graph_list.itemAt(graph_id).widget()
                self.ui_log.debug(f"Reseting values of existing graph ID{graph_id}")
                graph_box.reset_plot()
            self.ui_log.info("Starting traffic generation")
            self.monitoring_thread.start()
            self.monitoring_thread.finished.connect(self.finish_monitoring)
            self.monitoring_thread.new_data.connect(self.collect_new_data)
            self.monitoring_thread.stop_denied.connect(self.force_stop_traffic)
            self.unlock_button()

    def get_exec_options(self):
        exec_options = {}
        self.ui_log.info("Collecting TRex flags")
        exec_options["f"] = self.path.text()
        self.ui_log.debug(f"TRex profile: {exec_options['f']}")
        exec_options["d"] = self.duration.value()
        self.ui_log.debug(f"Duration: {exec_options['d']}")
        exec_options["m"] = self.rate.value()
        self.ui_log.debug(f"Rate multiplier: {exec_options['m']}")
        exec_options["arp-refresh-period"] = 5
        self.ui_log.debug(f"GARP refresh period: {exec_options['arp-refresh-period']}")
        exec_options["cfg"] = self.srv_con.push_custom_config(self._get_interfaces())
        if self.ipv6.isChecked():
            exec_options["ipv6"] = True
            self.ui_log.debug("IPv6 is enabled")
        else:
            self.ui_log.debug("IPv6 is disabled")
        if self.nat.isChecked():
            exec_options["learn-mode"] = 1
            self.ui_log.debug("Learn mode is set to 1")
        else:
            self.ui_log.debug("Learn mode is not set")
        return exec_options

    def collect_new_data(self, data):
        self.status.showMessage("Monitoring T-Rex operations")
        self.results.update_result_data(data)
        for graph_id in range(self.graph_list.count()):
            graph_box = self.graph_list.itemAt(graph_id).widget()
            if graph_box.plot_inited:
                graph_box.update_plot(self.results.get_last_value(graph_box.graph_query))
            else:
                graph_box.set_plot_init_data(self.results.get_value_list(graph_box.graph_query))
        with open("stat_template.html", "r") as f:
            details = "".join(f.readlines())
        details_map = {}
        details_map["$BPS"] = self.results.convert("bps", "throughput")
        details_map["$EXP_BPS"] = self.results.convert("bps", "expected_throughput")
        details_map["$PPS"] = self.results.convert("pps", "packet_rate")
        details_map["$EXP_PPS"] = self.results.convert("pps", "expected_packet_rate")
        details_map["$CPS"] = self.results.convert("cps", "connection_rate")
        details_map["$EXP_CPS"] = self.results.convert("cps", "expected_connection_rate")
        details_map["$CONN"] = self.results.convert("connections", "concurrent_connections")
        details_map["$DROP_BPS"] = self.results.convert("bps", "drop_rate")
        for i in details_map.keys():
            details = details.replace(i, details_map[i])
        self.exec_details.setText(details)

    def stop_traffic(self):
        self.monitoring_thread.stop()

    def force_stop_traffic(self):
        button_pressed = QtWidgets.QMessageBox.question(self, "Permission denied", 
                        "You are not allowed to stop traffic as it has been initiated by someone else\
                        Do you want to force traffic interruption?")
        if int(button_pressed) == 16384: # 16384 - Yes button; 65536 - No button
            self.monitoring_thread.force_stop()

    def finish_monitoring(self):
        self.status.showMessage("Traffic transmission has been finished")
        self.lock_button()
    
    def _get_interfaces(self):
        client_side = {}
        server_side = {}

        client_side["ip"] = self.client_box.ip.text()
        client_side["default_gw"] = self.client_box.next_hop.text()
        if self.client_box.vlan.text():
            client_side["vlan"] = self.client_box.vlan.text()

        server_side["ip"] = self.server_box.ip.text()
        server_side["default_gw"] = self.server_box.next_hop.text()
        if self.server_box.vlan.text():
            server_side["vlan"] = self.server_box.vlan.text()

        self.ui_log.debug(f"Interface 0 configuration: {client_side}")
        self.ui_log.debug(f"Interface 1 configuration: {server_side}")
        return [client_side, server_side]

    def trex_start_error(self, error_list):
        if not error_list:
            error_string = "Unknown error occured during initiating traffic\nCheck logs for more details"
        else:
            error_string = "\n".join(error_list)
        QtWidgets.QMessageBox.warning(self, "Failed to start T-Rex", error_string)

    def close_graph(self, graph_group_box):
        child_id = self.pcap_list.indexOf(graph_group_box)
        child = self.pcap_list.takeAt(child_id)
        if child.widget() is not None:
            child.widget().deleteLater()

    def new_profile(self):
        if not self.establish_connection():
            self.ui_log.warning("Connection to TRex server is required for creating new profile but can't be established")
            return
        profile = ProfileDialog(self, self.srv_con)
        if profile.exec_():
            file_name = profile.file_name
            profile_details = [profile.profile]
            self.ui_log.info(f"Profile {file_name} is ready to be saved")
            self.ui_log.debug(f"With following details:\n{profile_details}")
            file_path = self.srv_con.push_traffic_profile(file_name, profile_details)
            self.ui_log.debug(f"Profile has been saved to {file_path}")
            QtWidgets.QMessageBox.information(self, "Save file", 
                                                f"Traffic profile has been saved to {file_path}")
        else:
            self.ui_log.info("No profile to be saved")

    def edit_profile(self):
        if not self.establish_connection():
            self.ui_log.warning("Connection to TRex server is required for editing profile but can't be established")
            return
        profile = ProfileDialog(self, self.srv_con)
        profile.hide()
        profile.load()
        if profile.exec_():
            file_name = profile.file_name
            profile_details = [profile.profile]
            self.ui_log.info(f"Profile {file_name} is ready to be saved")
            self.ui_log.debug(f"With following details:\n{profile_details}")
            file_path = self.srv_con.push_traffic_profile(file_name, profile_details)
            self.ui_log.debug(f"Profile has been saved to {file_path}")
            QtWidgets.QMessageBox.information(self, "Save file", 
                                                f"Traffic profile has been saved to {file_path}")

    def add_graph(self):
        graph_options = {}
        graph_options["Throughput"] = ["throughput", "Data", "bps"]
        graph_options["Drop rate"] = ["drop_rate", "Data", "bps"]
        graph_options["Connection rate"] = ["connection_rate", "Connections", "cps"]
        graph_options["Packet rate"] = ["packet_rate", "Packets", "pps"]
        graph_options["Active flows"] = ["concurrent_connections", "Connections", "conn"]
        graph_types = []
        for graph_type in graph_options.keys():
            graph_types.append(graph_type)
        self.ui_log.info("Creating new graph")
        chose_graph = trex_ui.ChoseGraphDialog(self, graph_types)
        if chose_graph.exec_():
            graph_name = chose_graph.value
            self.ui_log.info(f"{graph_name} graph has been selected for creation")
            options = graph_options[graph_name]
            graph_box = trex_ui.GraphGroupBox(graph_name, options)
            self.graph_list.addWidget(graph_box)
            self.ui_log.info(f"{graph_name} graph has been created")
            graph_box.to_close.connect(self.close_group_box)
        else:
            self.ui_log.info("No graph has been chosen")

    def close_group_box(self, group_box):
        self.ui_log.info("Removing graph from the widget")
        child_id = self.graph_list.indexOf(group_box)
        child = self.graph_list.takeAt(child_id)
        if child.widget() is not None:
            self.ui_log.info(f"{child.widget().title()} graph has been chosen for deletion")
            child.widget().deleteLater()
            self.ui_log.info(f"{child.widget().title()} graph has been removed")


class ProfileDialog(trex_ui.ProfileDialog):

    def __init__(self, parent_object, connection):
        super().__init__(parent_object)

        self.log = logging.getLogger("trex.profile")

        self.srv_con = connection
        self.profile = {}
        self.file_name = ""
        self.load_profile.clicked.connect(self.load)
        self.upload_pcap.clicked.connect(self.upload)
        self.split_pcap.clicked.connect(self.split)
        self.add_pcap.clicked.connect(self.add)
        self.save_profile.clicked.connect(self.save)

    def load(self):
        ext = ".yaml"
        load_dialog = trex_ui.FileOpenDialog(self)
        file_tree = self.srv_con.get_file_tree(ext)
        load_dialog.fill_tree(file_tree, ext)
        if load_dialog.exec_():
            file_name = load_dialog.file
            data = self.srv_con.get_file(file_name, convert_yaml = True)
            self.name.setText(file_name.split("/")[-1])
            if "generator" in data[0].keys():
                if "clients_start" in data[0]["generator"].keys():
                    self.cstart.setText(data[0]["generator"]["clients_start"])
                if "clients_end" in data[0]["generator"].keys():
                    self.cend.setText(data[0]["generator"]["clients_end"])
                if "servers_start" in data[0]["generator"].keys():
                    self.sstart.setText(data[0]["generator"]["servers_start"])
                if "servers_end" in data[0]["generator"].keys():
                    self.send.setText(data[0]["generator"]["servers_end"])
            if "src_ipv6" in data[0].keys():
                self.sipv6.setText(self.convert_to_ipv6(data[0]["src_ipv6"]))
            if "dst_ipv6" in data[0].keys():
                self.dipv6.setText(self.convert_to_ipv6(data[0]["dst_ipv6"]))
            if "cap_ipg" in data[0].keys():
                self.ipg.setChecked(not data[0]["cap_ipg"])
            for pcap_details in data[0]["cap_info"]:
                pcap_group_box = trex_ui.PcapGroupBox(pcap_details["name"])
                if "ipg" in pcap_details.keys():
                    pcap_group_box.ipg.setText(str(pcap_details["ipg"]))
                if "cps" in pcap_details.keys():
                    pcap_group_box.cps.setText(str(pcap_details["cps"]))
                if "w" in pcap_details.keys():
                    pcap_group_box.w.setText(str(pcap_details["w"]))
                if "limit" in pcap_details.keys():
                    pcap_group_box.limit.setText(str(pcap_details["limit"]))
                self.pcap_list.addWidget(pcap_group_box)
                pcap_group_box.to_close.connect(self.close_group_box)                

    def upload(self):
        file_name = QtWidgets.QFileDialog.getOpenFileName(self, "Upload PCAP", 
                                                    "c:\\", "Traffic captures (*.cap *.pcap)")
        if not file_name[0]:
            return
        if self.srv_con.push_files(file_name[0]):
            QtWidgets.QMessageBox.information(self, "Upload PCAP", "File has been uploaded successfully")
        else:
            QtWidgets.QMessageBox.warning(self, "Upload PCAP", "Failed to upload the file")

    def split(self):
        
        self.file_name = QtWidgets.QFileDialog.getOpenFileName(self, "Split PCAP", 
                                                    "c:\\", "Traffic captures (*.cap *.pcap)")
        if not self.file_name[0]:
            self.log.info("No PCAP has been chosen to be analyzed")
            return
        self.progress = trex_ui.ProgressDialog(self)
        self.log.info(f"{self.file_name[0]} file to be analyzed")
        self.pcap_analyze = PcapAnalyzeThread(self.file_name[0])
        self.pcap_analyze.start()
        self.pcap_analyze.finished.connect(self.get_session_list)
        self.pcap_analyze.progress_updated.connect(self.update_progress_bar)

    def get_session_list(self, session_list):
        self.log.info(f"Loading list of TCP/UDP sessions from {self.file_name[0]}")
        self.progress.close()
        self.valid_sessions = session_list
        session_list_dialog = trex_ui.SessionListDialog(self)
        for session_tuple, session_details in self.valid_sessions.items():
            session_list_dialog.new_row(session_tuple, session_details)
        self.log.info("List of available sessions has been loaded")
        session_list_dialog.configure_sorting()
        if session_list_dialog.exec_():
            self.progress = trex_ui.ProgressDialog(self)
            self.log.info("Sending list of chosen sessions to be splitted to a separate thread")
            self.pcap_split = PcapSplitThread(self.file_name[0], session_list_dialog.session_list)
            self.pcap_split.start()
            self.pcap_split.finished.connect(self.load_file_list)
            self.pcap_split.progress_updated.connect(self.update_progress_bar)
        else:
            self.log.debug("Session list window has been closed no additional action required")
    
    def load_file_list(self, file_list):
        self.update_progress_bar(0)
        self.progress.progress_bar.setRange(0, len(file_list))
        uploaded = 0
        self.log.info(f"Sending {len(file_list)} PCAP file(s) to TRex server")
        for _, file_name in file_list.items():
            self.log.info(f"Sending {file_name[0]}/{file_name[1]}")
            if self.srv_con.push_files(str(pathlib.PurePath(file_name[0], file_name[1]))):
                uploaded += 1
                self.update_progress_bar(uploaded)
                pcap_group_box = trex_ui.PcapGroupBox(f"{TREX_TMP}/{file_name[1]}")
                self.pcap_list.addWidget(pcap_group_box)
                pcap_group_box.to_close.connect(self.close_group_box)
        self.progress.close()

    def update_progress_bar(self, new_value):
        self.progress.progress_bar.setValue(new_value)

    def add(self):
        ext = (".cap", ".pcap")
        open_dialog = trex_ui.FileOpenDialog(self)
        file_tree = self.srv_con.get_file_tree(ext)
        open_dialog.fill_tree(file_tree, ext)
        if open_dialog.exec_():
            file_name = open_dialog.file
            self.log.info(f"Adding {file_name} to the profile")
            pcap_group_box = trex_ui.PcapGroupBox(file_name)
            self.pcap_list.addWidget(pcap_group_box)
            pcap_group_box.to_close.connect(self.close_group_box)
        else:
            self.log.info(f"No PCAP file has been selected to be added to profile")

    def save(self):
        if self.name.text().endswith(".yaml"):
            self.file_name = self.name.text()
        else:
            self.log.debug("No extension has been specified for the name of the file. Adding .yaml")
            self.file_name = f"{self.name.text()}.yaml"
        self.profile["duration"] = 30
        self.profile["generator"] = {"distribution" : "seq",
                                     "tcp_aging" : "0",
                                     "udp_aging" : "0",
                                     "clients_start" : self.cstart.text(),
                                     "clients_end" : self.cend.text(),
                                     "servers_start" : self.sstart.text(),
                                     "servers_end" : self.send.text()}
        if self.ipg.isChecked():
            self.profile["cap_ipg"] = False
        else:
            self.profile["cap_ipg"] = True

        if self.sipv6.text():
            self.profile["src_ipv6"] = self.convert_ipv6(self.sipv6.text())
        if self.dipv6.text():
            self.profile["dst_ipv6"] = self.convert_ipv6(self.dipv6.text())

        self.profile["cap_info"] = []
        for pcap_id in range(self.pcap_list.count()):
            pcap = self.pcap_list.itemAt(pcap_id).widget()
            pcap_details = {}
            pcap_details["name"] = pcap.title()
            pcap_details["cps"] = pcap.cps.text()
            pcap_details["ipg"] = pcap.ipg.text()
            pcap_details["rtt"] = pcap.ipg.text()
            pcap_details["w"] = pcap.w.text()
            if pcap.limit.text():
                pcap_details["limit"] = pcap.limit.text()
            self.profile["cap_info"].append(pcap_details)
        self.log.info("Profile has been generated")
        self.accept()

    def close_group_box(self, pcap_group_box):
        child_id = self.pcap_list.indexOf(pcap_group_box)
        child = self.pcap_list.takeAt(child_id)
        if child.widget() is not None:
            child.widget().deleteLater()

    def convert_ipv6(self, prefix):
        ipv6_as_list = []
        if prefix.startswith("::"):
            prefix = f"0{prefix}"
        if prefix.endswith("::"):
            prefix = f"{prefix}0"
        temp = prefix.split(":")
        for hextet in temp:
            if hextet:
                for _ in range(4 - len(hextet)):
                    hextet = f"0{hextet}"
                hextet = f"0x{hextet}"
                ipv6_as_list.append(hextet)
            else:
                for _ in range(6 - len(temp) + 1):
                    ipv6_as_list.append("0x0000")
        for _ in range (6 - len(ipv6_as_list)):
            ipv6_as_list.append("0x0000")
        self.log.debug(f"IPv6 address {prefix} is translated as {ipv6_as_list}")
        return ipv6_as_list

    def convert_to_ipv6(self, hextet_list):
        ipv6_address = ""
        for i in range(len(hextet_list)):
            if type(hextet_list[i]) is int:
                hextet = format(hextet_list[i], "X")
                for _ in range(4 - len(hextet)):
                    hextet = f"0{hextet}"
                ipv6_address += hextet
            else:
                ipv6_address += hextet_list[i][2:]
            if i < len(hextet_list) - 1:
                ipv6_address += ":"
        self.log.debug(f"Hextet list {hextet_list} is translated as {ipv6_address}")
        return ipv6_address

class PcapAnalyzeThread(QtCore.QThread):

    finished = QtCore.pyqtSignal(dict)
    progress_updated = QtCore.pyqtSignal(int)

    def __init__(self, filename):
        QtCore.QThread.__init__(self)
        self.filename = filename
        self.log = logging.getLogger("trex.pcap_analyze")

    def run(self):
        self.log.info(f"Trying to analyze {self.filename}")
        session_list = splitter.get_session_list(self.filename, parent_thread = self)
        self.log.info(f"Finished {self.filename} analyzing")
        self.finished.emit(session_list)

    def update_progress(self, new_value):
            self.progress_updated.emit(new_value)

class PcapSplitThread(QtCore.QThread):

    finished = QtCore.pyqtSignal(dict)
    progress_updated = QtCore.pyqtSignal(int)

    def __init__(self, filename, session_list):
        QtCore.QThread.__init__(self)
        self.filename = filename
        self.session_list = session_list
        self.log = logging.getLogger("trex.pcap_split")

    def run(self):
        self.log.info(f"Trying to split {self.filename}")
        self.log.debug(f"List of sessions to be splitted:\n{self.session_list}")
        files = splitter.split_pcap(self.filename, self.session_list, parent_thread = self)
        self.log.info(f"Finished {self.filename} splitting")
        self.finished.emit(files)

    def update_progress(self, new_value):
            self.progress_updated.emit(new_value)

class TrexThread(QtCore.QThread):

    new_data = QtCore.pyqtSignal(dict)
    finished = QtCore.pyqtSignal()
    start_error = QtCore.pyqtSignal(list)
    stop_denied = QtCore.pyqtSignal()

    def __init__(self, connection, config):
        self.log = logging.getLogger("trex.monitor")
        self.log.info("Initiating TRex monitoring thread")
        QtCore.QThread.__init__(self)
        self.config = config
        self.connection = connection
        self.need_to_finish = False

    def __del__(self):
        self.wait()

    def stop(self):
        self.need_to_finish = True
    
    def force_stop(self):
        self.log.info("Force killing of running TRex process")
        self.connection.force_kill()

    def run(self):
        if not self.connection.check_status():
            try:
                self.connection.start_trex(self.config)
                self.log.info(f"New TRex process has been started. Parameters: {self.config}")
            except Exception as e:
                self.log.error(f"Failed to start new TRex process\n{e}")
                self.handle_exception(e)
        try:
            self.monitoring()
        except Exception as e:
            self.log.error(f"Monitoring has been finished unexpectedly\n{e}")
            self.finished.emit()


    def monitoring(self):
        while True:
            try:
                if not self.connection.check_status():
                    self.log.info("TRex traffic has been stopped. Need to finish monitoring.")
                    self.finished.emit()
                    break
                data = self.connection.get_data()
            except TimeoutError:
                self.log.error("Timeout occurred. Monitoring will be resumed in 1 second")
                time.sleep(1)
                continue
            self.new_data.emit(data)
            if self.need_to_finish:
                self.need_to_finish = False
                try:
                    self.log.debug("Trying to stop traffic execution")
                    self.connection.stop_trex()
                    self.finished.emit()
                    break
                except trex_exceptions.TRexRequestDenied:
                    self.log.warning("Can't stop traffic gracefully")
                    self.stop_denied.emit()
            time.sleep(1)

    def collect_data(self):
        self.connection.get_data()

    def handle_exception(self, err):
        error_list = []
        trex_output = str(err).split("\n")
        for output_string in trex_output:
            if output_string.startswith("Failed resolving dest MAC"):
                error_list.append("Failed to resolve MAC address of the next-hop")
            elif "The number of clients requested is" in output_string:
                error_list.append("Failed to handle more than 1 000 000 clients/servers")
            elif "Error: non valid ip" in output_string:
                error_list.append("Invalid IP address in configuration")
            elif "value of field 'vlan' must be between" in output_string:
                error_list.append("VLAN ID should be between 0 and 4096 or empty for no tagging")
            elif "The number of ips should be at least number of threads" in output_string:
                error_list.append("The number of IP address should be equal or more than number of threads")
            elif "invalid coremask" in output_string or "Number of TX queues exceeds" in output_string:
                error_list.append("Invalid amount of threads")
            elif "not enough flow objects" in output_string:
                error_list.append("Active flows threshold exceed")
            elif "Unsupported CAP format" in output_string:
                file = output_string.split(":")[1].strip()
                error_list.append(f"Failed to handle {file} file")
            elif "Bad cap file timings" in output_string:
                error_list.append("Incorrect IPG in TCP handshake")
            elif "Error parsing file" in output_string:
                error_list.append("Invalid profile format")
            elif "ERROR file" in output_string and output_string.endswith("does not exist"):
                error_list.append("Profile does not exist")
            elif "run failed due to wrong input parameters" in output_string:
                error_list.append("Invalid option has been specified")
            elif "--learn mode is not supported with --ipv6" in output_string:
                error_list.append("NAT is not supported with IPv6")
        self.log.debug(f"Failure reason(s): {error_list}")
        self.start_error.emit(error_list)
        


class Client:

    def __init__(self, srv_ip):
        self.log = logging.getLogger("trex.client")
        self.log.info("Initiating connection to TRex server")
        self.trex_connect = CTRexClient(srv_ip, timeout=300)
        self.lock = Lock()

    def check_connection(self):
        status = {"server_status" : False, "master_status" : False}
        try:
            with self.lock:
                self.log.debug("Trying to check server connectivity")
                self.trex_connect.check_server_connectivity()
            self.log.debug("TRex server is up")
            status["server_status"] = True
        except:
            self.log.debug("TRex server is down")
            return status

        try:
            with self.lock:
                self.log.debug("Trying to check master daemon status")
                self.trex_connect.check_master_connectivity()
            self.log.debug("Master daemon is up")
            status["master_status"] = True
        except:
            self.log.debug("Master daemon is down")
            pass
        
        if status["master_status"]:
            with self.lock:
                status["is_trex_daemon_running"] = self.trex_connect.is_trex_daemon_running()
                if status["is_trex_daemon_running"]:
                    self.log.debug("TRex daemon is up")
                else:
                    self.log.debug("TRex daemon is down")
                status["trex_path"] = self.trex_connect.get_trex_path()

        if status["server_status"]:
            with self.lock:
                status["is_reserved"] = self.trex_connect.is_reserved()
                self.log.info(f"Is trex reserved: {status['is_reserved']}")
                status["is_idle"] = self.trex_connect.is_idle()
                self.log.info(f"Is trex idle: {status['is_idle']}")
                status["running_status"] = self.trex_connect.get_running_status()
                self.log.info(f"TRex running status: {status['running_status']}")
                status["trex_cmds"] = self.trex_connect.get_trex_cmds()
                self.log.info(f"TRex processes: {status['trex_cmds']}")

        return status

    def start_trex(self, config):
        with self.lock:
            if self.trex_connect.start_trex(**config):
                self.log.info("Traffic is initiated successfully")

    def restart_trex(self):
        with self.lock:
            self.log.info("Restarting TRex daemon")
            self.trex_connect.restart_trex_daemon()
        
    def check_status(self):
        with self.lock:
            status = not self.trex_connect.is_idle()
            self.log.debug(f"Checking traffic status. Is it running: {status}")
        return status

    def get_data(self):
        with self.lock:
            info = self.trex_connect.get_running_info()
        return info

    def get_trex_path(self):
        with self.lock:
            path = self.trex_connect.get_trex_path()
            self.log.info(f"Trex path is {path}")
        return path
    
    def push_files(self, files):
        with self.lock:
            push_status = self.trex_connect.push_files(files)
            if push_status:
                self.log.info(f"{files} has been saved on TRex server")
        return push_status

    def get_file_tree(self, ext):
        trex_path = self.get_trex_path()
        tmp_path = TREX_TMP
        file_tree = {}
        file_tree[trex_path] = self._get_file_tree(trex_path, ext)
        file_tree[tmp_path] = self._get_file_tree(tmp_path, ext)
        self.log.info(f"File tree for {trex_path}/ and {tmp_path} has been created")
        return file_tree

    def _get_file_tree(self, path, ext):
        self.log.info(f"Loading list of files from {path} directory with {ext} extension")
        with self.lock:
            folders, files = self.trex_connect.get_files_list(path)
            self.log.debug(f"Got list of files and directories in {path}")
        file_list = []
        files_tree = {}
        service_folder_list = ["external_libs", "trex_client", "python-lib", 
                                "automation", "astf", "stl", "avl", "cfg", "ko"]
        for file in files:
            if file.endswith(ext):
                self.log.debug(f"{file} matches to the {ext} extension")
                file_list.append(file)
            else:
                self.log.debug(f"{file} doesn't match to the {ext} extension")
        if file_list:
            files_tree["."] = file_list
        for folder in folders:
            if folder in service_folder_list:
                self.log.debug(f"{folder} is in the list of service directories. Continue with no action")
                continue
            nested_path = f"{path}/{folder}"
            nested_tree = self._get_file_tree(nested_path, ext)
            if nested_tree:
                files_tree[folder] = nested_tree
            else:
                self.log.debug(f"{path}/{folder} is empty")
        return files_tree

    def get_file(self, file, convert_yaml = True):
        with self.lock:
            file_bytes = self.trex_connect.get_file(file)
            self.log.info(f"{file} has been loaded")
        if convert_yaml:
            yaml_format = yaml.load(file_bytes)
            self.log.debug(f"YAML {file} file has been converted")
            return yaml_format
        else:
            self.log.debug(f"No need to convert {file} file")
            return file_bytes

    def push_traffic_profile(self, name, data):
        tmp_path = TREX_TMP
        with open(name, "w") as f:
            yaml.dump(data, f, default_flow_style=False)
            self.log.info(f"Traffic profile {name} has been created")
        self.push_files(name)
        self.log.info(f"{name} file has been saved to {tmp_path}/ folder")
        os.remove(name)
        self.log.debug(f"{name} has been deleted from local machine")
        return f"{tmp_path}/{name}"

    def push_custom_config(self, port_info):
        tmp_path = TREX_TMP
        platform_config = "platform_config.yaml"
        with self.lock:
            interfaces = yaml.load(self.trex_connect.get_trex_config())[0]["interfaces"]
            self.log.info(f"List of interfaces is configured in /etc/trex.yaml: {interfaces}")
        config = [{"port_limit" : 2, 
                   "version" : 2,
                   "interfaces" : interfaces,
                   "port_info" : port_info}]
        with open(platform_config, "w") as f:
            yaml.dump(config, f)
            self.log.info(f"Custom platform configuration file has been created: {config}")
        self.push_files(platform_config)
        self.log.info(f"{platform_config} file has been saved to {tmp_path}/ folder")
        os.remove(platform_config)
        self.log.debug(f"{platform_config} has been deleted from local machine")
        return f"{tmp_path}/{platform_config}"

    def stop_trex(self):
        with self.lock:
            if self.trex_connect.stop_trex():
                self.log.info("Traffic has been stopped successfully")

    def force_kill(self):
        with self.lock:
            self.trex_connect.force_kill(confirm=False)


class Results:

    def __init__(self):
        self.value = {}
        self.log = logging.getLogger("trex.result")
        self.clear_results()
        self.lock = False

    def clear_results(self):
        self.log.info("Clearing all results")
        self.values = {"calculated_throughput": [],
                       "calculated_drop_rate": [],
                       "throughput": [],
                       "drop_rate": [],
                       "connection_rate": [],
                       "concurrent_connections": [],
                       "packet_rate": [],
                       "expected_throughput": [],
                       "expected_packet_rate": [],
                       "expected_connection_rate": [],
                       "tx_packets": [],
                       "rx_packets": [],
                       "tx_bytes": [],
                       "rx_bytes": [],
                       "timestamp": []}

    def update_result_data(self, new_data):
        self.values["timestamp"].append(time.time())
        self.values["throughput"].append(new_data["trex-global"]["data"]["m_rx_bps"])
        self.values["drop_rate"].append(new_data["trex-global"]["data"]["m_rx_drop_bps"])
        self.values["connection_rate"].append(new_data["trex-global"]["data"]["m_tx_cps"])
        self.values["concurrent_connections"].append(new_data["trex-global"]["data"]["m_active_flows"])
        self.values["packet_rate"].append(new_data["trex-global"]["data"]["m_tx_pps"])
        self.values["expected_throughput"].append(new_data["trex-global"]["data"]["m_tx_expected_bps"])
        self.values["expected_packet_rate"].append(new_data["trex-global"]["data"]["m_tx_expected_pps"])
        self.values["expected_connection_rate"].append(new_data["trex-global"]["data"]["m_tx_expected_cps"])
        self.values["tx_packets"].append(new_data["trex-global"]["data"]["m_total_tx_pkts"])
        self.values["rx_packets"].append(new_data["trex-global"]["data"]["m_total_rx_pkts"])
        self.values["tx_bytes"].append(new_data["trex-global"]["data"]["m_total_tx_bytes"])
        self.values["rx_bytes"].append(new_data["trex-global"]["data"]["m_total_rx_bytes"])
        self._calculate()
        item_amount = len(self.values["timestamp"])
        for i in self.values.keys():
            if len(self.values[i]) != item_amount:
                self.log.error(f"Incorrect amount of items in {i} list")

    def _calculate(self):
        if len(self.values["rx_bytes"]) < 2:
            self.values["calculated_throughput"].append(0)
            self.values["calculated_drop_rate"].append(0)
            return
        time_delta = self.values["timestamp"][-1] - self.values["timestamp"][-2]
        throughput = int(8 * (self.values["rx_bytes"][-1] - self.values["rx_bytes"][-2]) // time_delta)
        expected_throughput = int(8 * (self.values["tx_bytes"][-1] - self.values["tx_bytes"][-2]) // time_delta)
        drop_rate = expected_throughput - throughput
        self.values["calculated_throughput"].append(throughput)
        self.values["calculated_drop_rate"].append(drop_rate)

    def get_last_value(self, key):
        if key not in self.values.keys():
            self.log.warning(f"Incorrect request for {key} element from results table")
            return 0
        if not self.values[key]:
            self.log.warning(f"{key} has no values available in results table")
            return 0
        else:
            return self.values[key][-1]

    def get_value_list(self, key):
        return self.values[key][:]

    def convert(self, type, key):
        value = self.get_last_value(key)
        if type == "bps":
            return self._convert_bps(value)
        if type == "bytes":
            return self._convert_bytes(value)
        elif type == "pps":
            return self._convert_pps(value)
        elif type == "packets":
            return self._convert_packets(value)
        elif type == "connections":
            return self._convert_conn(value)
        elif type == "cps":
            return self._convert_cps(value)
        elif type == "percent":
            return self._convert_percent(value)

    def _convert_bps(self, value):
        return f"{self._set_prefix(value)}bps"

    def _convert_bytes(self, value):
        return f"{self._set_prefix(value)}B"

    def _convert_conn(self, value):
        return f"{self._set_prefix(value)}conn"

    def _convert_cps(self, value):
        return f"{self._set_prefix(value)}cps"

    def _convert_packets(self, value):
        return f"{self._set_prefix(value)}pkt"

    def _convert_pps(self, value):
        return f"{self._set_prefix(value)}pps"

    def _set_prefix(self, value):
        try:
            value = float(value)
        except:
            return "0 "
        if not value:
            return "0 "
        elif value < 1000:
            return f"{int(value)} "
        elif value < 1000*1000:
            return f"{round(value/1000,2)} K"
        elif value < 1000*1000*1000:
            return f"{round(value/1000000,2)} M"
        elif value < 1000*1000*1000*1000:
            return f"{round(value/1000000000,2)} G"
        elif value < 1000*1000*1000*1000*1000:
            return f"{round(value/1000000000000,2)} T"
        return str(value)

    def _convert_percent(self, value):
        try:
            value = int(value*100)
        except:
            return "0"
        if not value:
            return "0 %"
        else:
            return f"{value} %"
        return str(value)

if __name__ == "__main__":
    """
    logging.basicConfig(level=logging.DEBUG,
                        filename="app.log",
                        datefmt="%d/%m/%y %H:%M:%S",
                        filemode="a",
                        format="%(asctime)s %(name)-12s %(levelname)-8s %(message)s")"""
    log = logging.getLogger("trex")
    log.setLevel(logging.DEBUG)
    log_format = logging.Formatter(fmt = "%(asctime)s %(name)s %(levelname)s %(message)s",
                                   datefmt = "%d/%m/%y %H:%M:%S")
    log_handler = logging.handlers.RotatingFileHandler(filename = "app.log",
                                                       mode = "a",
                                                       maxBytes = 10*1024*1024,
                                                       backupCount = 10)
    log_handler.setFormatter(log_format)
    log.addHandler(log_handler)

    log_split = logging.getLogger("splitter")
    log_split.setLevel(logging.DEBUG)
    log_split_format = logging.Formatter(fmt = "%(asctime)s %(name)s %(levelname)s %(message)s",
                                         datefmt = "%d/%m/%y %H:%M:%S")
    log_split_handler = logging.handlers.RotatingFileHandler(filename = "pcap.log",
                                                             mode = "a",
                                                             maxBytes = 10*1024*1024,
                                                             backupCount = 10)
    log_split_handler.setFormatter(log_split_format)
    log_split.addHandler(log_split_handler)

    app = QtWidgets.QApplication(sys.argv)
    window = Window()
    sys.exit(app.exec_())