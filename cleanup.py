import os
import shutil

def clean_folder(folder_path):
    """Remove all files in a folder but keep the folder"""
    if os.path.exists(folder_path):
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                    print(f"Deleted: {file_path}")
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
                    print(f"Deleted directory: {file_path}")
            except Exception as e:
                print(f"Error deleting {file_path}: {e}")

if __name__ == "__main__":
    folders_to_clean = [
        'encrypted',
        'raw_data',
        'key',
        'uploads',
        'files',
        'restored_file'
    ]
    
    for folder in folders_to_clean:
        print(f"\nCleaning {folder}/...")
        clean_folder(folder)
    
    print("\n✓ Cleanup complete!")
