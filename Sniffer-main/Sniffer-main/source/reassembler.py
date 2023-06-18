import copy
import signal
from packet import PacketInfo


class Reassembler:
    def __init__(self):
        self.packet_list = []
        self.signals = signal.Signals()
        self.number = 0
        self.result_dict = {}
        self.result_list = []

        # self.reassemble_packet()

    def reassemble_packet(self, packet_list):
        self.packet_list = packet_list
        self.result_dict.clear()
        self.result_list.clear()
        self.number = 0

        id_dict = {}
        for pkt in self.packet_list:
            detail_dict = copy.deepcopy(pkt.detail_info)
            if detail_dict['IP']['id(标识)'] not in id_dict.keys():
                id_dict[str(detail_dict['IP']['id(标识)'])] = []
                id_dict[str(detail_dict['IP']['id(标识)'])].append(detail_dict)
            else:
                id_dict[str(detail_dict['IP']['id(标识)'])].append(detail_dict)

        for id_key in id_dict.keys():
            tmp_dict = {}

            if len(id_dict[id_key]) < 2:
                return 0

            for pkt in id_dict[id_key]:
                tmp_dict[str(pkt['IP']['frag(段偏移)'])] = pkt
            self.result_dict[id_key] = tmp_dict['0']
            contents = ''
            total_len = -20 * (len(tmp_dict) - 1)

            for frag in sorted(tmp_dict.keys()):
                contents += tmp_dict[frag]['Raw']['load']
                total_len += int(tmp_dict[frag]['IP']['len(总长度)'])

            self.result_dict[id_key]['IP']['len(总长度)'] = str(total_len)
            self.result_dict[id_key]['Raw']['load'] = contents
            self.result_dict[id_key]['IP']['flags(分段标志)'] = 'DF'
            self.result_dict[id_key]['IP']['frag(段偏移)'] = str(0)

            hex_info = ''
            for pkt in self.packet_list:
                src = pkt.src
                dst = pkt.dst
                raw_data = pkt.raw_data
                hex_info += pkt.hex_info

            length = total_len + 14
            protocol = self.packet_list[0].protocol
            info = self.packet_list[0].info

            # print(src, dst, protocol, length, info, raw_data, hex_info)
            packet_info = PacketInfo()
            packet_info.from_args(self.number, 0, src, dst, protocol, length, info, raw_data, hex_info)
            self.number += 1
            self.signals.update_reassemble_table.emit(packet_info)

        if self.result_dict:
            for v in self.result_dict.values():
                self.result_list.append(v)
            # print(self.result_list)
        return 1
