import os
import zipfile

EXCLUDE_DIRS = {
    'node_modules',
    'dist',
    'build',
    '.git',
    '.aistudio',
    'coverage',
    'tmp',
    '.vscode',
    '.idea',
    '__pycache__'
}

EXCLUDE_EXTS = {
    '.log',
    '.tmp',
    '.DS_Store'
}

EXCLUDE_FILES = {
    'sindh-cyber-saathi-project.zip',
    '.env',
    '.env.local',
    '.env.production'
}

def create_project_zip(output_path, source_dir):
    print(f"Creating project zip at {output_path} from {source_dir}...")
    file_count = 0
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(source_dir):
            # Modify dirs in-place to avoid descending into excluded directories
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            
            for file in files:
                if file in EXCLUDE_FILES:
                    continue
                _, ext = os.path.splitext(file)
                if ext in EXCLUDE_EXTS:
                    continue
                if file.startswith('applet-') and file.endswith('.png'):
                    continue
                
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, source_dir)
                zipf.write(full_path, arcname=rel_path)
                file_count += 1
                
    print(f"Successfully packaged {file_count} files into {output_path} ({os.path.getsize(output_path)} bytes).")

if __name__ == '__main__':
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    public_zip = os.path.join(root_dir, 'public', 'sindh-cyber-saathi-project.zip')
    create_project_zip(public_zip, root_dir)
