"""Same core tools, restricted to the images explicitly selected for one UI case."""
import json
import sys
from pathlib import Path
from .backend import VolatilityBackend, EvidenceError, file_fingerprint, SUPPORTED_EXTENSIONS
from .relocation import logical_path
from .config import Config
from .server import create_server


class CaseBackend(VolatilityBackend):
    def __init__(self, config, images):
        super().__init__(config)
        self.allowed = set()
        for value in images:
            candidate = logical_path(Path(value).expanduser())
            if not candidate.is_absolute():
                candidate = self.cases / candidate
            self._check_components(candidate)
            path = super().authorize_saved_image(str(candidate))
            if path.exists():
                path = super().resolve_input(str(path))
            elif path.suffix.lower() not in SUPPORTED_EXTENSIONS:
                raise EvidenceError('Supported memory-image extensions: ' + ', '.join(sorted(SUPPORTED_EXTENSIONS)))
            self.allowed.add(str(path))

    def resolve_input(self, value, *, memory_image=True):
        path = super().resolve_input(value, memory_image=memory_image)
        if str(path) not in self.allowed:
            raise EvidenceError('This file is not registered in the active UI case.')
        return path

    def authorize_saved_image(self, value):
        path = super().authorize_saved_image(value)
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
