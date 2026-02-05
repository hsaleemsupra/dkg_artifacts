import os
from json import load, JSONDecodeError


class SettingsError(Exception):
    pass


class Settings:
    def __init__(
        self,
        deploy_key_name,
        repo_name,
        repo_url,
        instance_type,
        aws_regions,
        from_port,
        to_port,
    ):
        inputs_str = [
            repo_name, repo_url, instance_type
        ]
        if isinstance(aws_regions, list):
            regions = aws_regions
        else:
            regions = [aws_regions]
        inputs_str += regions
        ok = all(isinstance(x, str) for x in inputs_str)
        ok &= isinstance(from_port, int)
        ok &= isinstance(to_port, int)
        ok &= len(regions) > 0
        if not ok:
            raise SettingsError('Invalid settings types')

        self.github_deploy_key_name = deploy_key_name
        self.github_deploy_key_path = os.environ.get("GITHUB_DEPLOY_KEY_PATH") + "/" + deploy_key_name
        self.instance_key = os.environ.get("INSTANCE_KEY")
        self.instance_key_name = os.environ.get("INSTANCE_KEY_NAME")
        self.repo_name = repo_name
        self.repo_url = repo_url
        self.branch = os.environ.get("GIT_BRANCH")
        self.instance_name = os.environ.get("INSTANCE_NAME")
        self.instance_type = instance_type
        self.aws_regions = regions
        self.from_port = from_port
        self.to_port = to_port

    @classmethod
    def load(cls, filename):
        try:
            with open(filename, 'r') as f:
                data = load(f)

            return cls(
                data['github_deploy_key']['name'],
                data['repo']['name'],
                data['repo']['url'],
                data['instances']['type'],
                data['instances']['regions'],
                data['port']['fromPort'],
                data['port']['toPort'],
            )
        except (OSError, JSONDecodeError) as e:
            raise SettingsError(str(e))

        except KeyError as e:
            raise SettingsError(f'Malformed settings: missing key {e}')
