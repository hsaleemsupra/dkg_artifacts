from json import dump, load


class ConfigError(Exception):
    pass


class ChainParameters:
    def __init__(self, json):
        try:
            value = json['network_config']
            value = json['dkg_config']
            value = json['batch_config']
            value = json['delivery_config']
        except KeyError as e:
            raise ConfigError(f'Malformed parameters: missing key {e}')

        self.json = json

    def print(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'w') as f:
            dump(self.json, f, indent=4, sort_keys=True)

    @staticmethod
    def load(filename):
        assert isinstance(filename, str)
        with open(filename, 'r') as f:
            data = load(f)
            return ChainParameters(data)

    def print_network_config(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'w') as f:
            dump(self.json['network_config'], f, indent=4, sort_keys=True)

    def tribes(self):
        try:
            return self.json['network_config']['tribes']
        except KeyError as e:
            raise ConfigError(f'Malformed parameters: missing key {e}')

    def clans(self):
        try:
            return self.json['network_config']['clans']
        except KeyError as e:
            raise ConfigError(f'Malformed parameters: missing key {e}')

    def peers(self):
        try:
            return self.json['network_config']['clan_size']
        except KeyError as e:
            raise ConfigError(f'Malformed parameters: missing key {e}')

    def chain_size(self):
        return int(self.tribes()) * int(self.clans()) * int(self.peers())
