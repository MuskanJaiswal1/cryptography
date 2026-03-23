import config
import tools


def restore():
    tools.empty_folder(str(config.RESTORED_FILES_FOLDER))

    chapters = 0

    meta_data = open(str(config.RAW_DATA_FOLDER / 'meta_data.txt'), 'r', encoding='utf-8')
    meta_info = []
    for row in meta_data:
        temp = row.split('\n')
        temp = temp[0]
        temp = temp.split('=')
        meta_info.append(temp[1])
    address = config.RESTORED_FILES_FOLDER / meta_info[0]

    list_of_files = sorted(tools.list_dir(str(config.TEMP_FILES_FOLDER)))

    with open(address, 'wb') as writer:
        for file in list_of_files:
            path = config.TEMP_FILES_FOLDER / file
            with open(path, 'rb') as reader:
                for line in reader:
                    writer.write(line)
                reader.close()
        writer.close()

    tools.empty_folder(str(config.TEMP_FILES_FOLDER))
