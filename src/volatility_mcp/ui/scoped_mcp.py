"""Same core tools, restricted to the images explicitly selected for one UI case."""
import json
import sys
from pathlib import Path
from ..backend import VolatilityBackend, EvidenceError, file_fingerprint
from ..config import Config
from ..server import create_server


class CaseBackend(VolatilityBackend):
    def __init__(self, config, images):
        super().__init__(config)
        self.allowed = {str(super(CaseBackend, self).resolve_input(p)) for p in images}

    def resolve_input(self, value, *, memory_image=True):
        path = super().resolve_input(value, memory_image=memory_image)
        if str(path) not in self.allowed:
            raise EvidenceError('This file is not registered in the active UI case.')
        return path

    def list_memory_images(self):
        images = [file_fingerprint(self.resolve_input(p)) for p in sorted(self.allowed)]
        return {'count': len(images), 'images': images}


def main():
    data = json.loads(Path(sys.argv[1]).read_text())
    config = Config.from_dict(data['config'])
    create_server(config, backend=CaseBackend(config, data['images'])).run(transport='stdio')


if __name__ == '__main__':
    main()
