import os
import config
import tools


def divide():
    """
    Split a file into chunks of configurable size.
    
    Creates numbered chunk files (SECRET0000000, SECRET0000001, etc.)
    and metadata file with original filename and chunk count.
    """
    tools.empty_folder(str(config.TEMP_FILES_FOLDER))
    os.makedirs(str(config.RAW_DATA_FOLDER), exist_ok=True)

    # Reset active metadata file for the current upload only.
    metadata_path = config.RAW_DATA_FOLDER / 'meta_data.txt'
    if metadata_path.exists():
        os.remove(str(metadata_path))
    FILE = tools.list_dir(str(config.UPLOAD_FOLDER))
    FILE = str(config.UPLOAD_FOLDER / FILE[0])

    CHUNK_SIZE = config.CHUNK_SIZE  # 32 KB - configurable chunk size

    chapters = 0
    meta_data = open(str(config.RAW_DATA_FOLDER / 'meta_data.txt'), 'w', encoding='utf-8')
    file__name = os.path.basename(FILE)  # Cross-platform way to get filename
    print(file__name)
    meta_data.write("File_Name=%s\n" % (file__name))
    
    with open(FILE, 'rb') as src:
        while True:
            chunk_data = src.read(CHUNK_SIZE)
            if not chunk_data:
                break
            
            chunk_filename = str(config.TEMP_FILES_FOLDER / ('SECRET' + '%07d' % chapters))
            with open(chunk_filename, 'wb') as target_file:
                target_file.write(chunk_data)
            
            chapters += 1
    
    meta_data.write("chapters=%d" % chapters)
    meta_data.close()
