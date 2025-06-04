#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

// End of chain marker
#define FAT_EOC 0xFFFF
// Filesystem signature
#define FS_SIGNATURE "ECS150FS"

// Data Structs 
struct __attribute__((packed)) superblock {
	uint8_t signature[8];
	uint16_t total_blocks;
	uint16_t root_dir_index;
	uint16_t data_start_index;
	uint16_t data_block_count;
	uint8_t fat_block_count;
	uint8_t padding[4079];
};

struct __attribute__((packed)) root_entry {
	uint8_t filename[FS_FILENAME_LEN];
	uint32_t file_size;
	uint16_t first_data_block;
	uint8_t padding[10];
};

/* Struct to track open files */
static struct {
	int in_use; // 1 = in_use
	int root_index;
	size_t offset;
} open_files[FS_OPEN_MAX_COUNT];

// Global Vars
static struct superblock sb;
static uint16_t *fat = NULL;
static struct root_entry root_dir[FS_FILE_MAX_COUNT];
static int mounted = 0;

/* Helper function prototypes */
static int write_root(void);
static int write_fat(void);
static uint16_t find_free_block(void);

int fs_mount(const char *diskname)
{
	uint8_t block[BLOCK_SIZE];
	size_t fat_size_bytes;

	// Check if mounted
	if (mounted) {
		return -1;
	}

	// Open the disk
	if (block_disk_open(diskname) < 0) {
		return -1;
	}

	// Read the superblock
	if (block_read(0, block) < 0) {
		block_disk_close();
		return -1;
	}
	memcpy(&sb, block, sizeof(sb));

	// Verify filesystem signature
	if (memcmp(sb.signature, FS_SIGNATURE, 8) != 0) {
    	block_disk_close();
    	return -1;
	}

	// Verify total block count matches disk
	int disk_block_count = block_disk_count();
	if (disk_block_count < 0 || sb.total_blocks != (uint16_t)disk_block_count) {
    	block_disk_close();
    	return -1;
	}

	// Validate superblock values to prevent buffer overflows
	if (sb.data_block_count == 0 || sb.fat_block_count == 0) {
		block_disk_close();
		return -1;
	}

	// Calculate expected FAT size and validate
	fat_size_bytes = sb.data_block_count * sizeof(uint16_t);
	size_t expected_fat_blocks = (fat_size_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;
	if (sb.fat_block_count != expected_fat_blocks) {
		block_disk_close();
		return -1;
	}

	// Allocate memory for FAT - allocate full blocks worth to avoid partial block issues
	size_t fat_alloc_size = sb.fat_block_count * BLOCK_SIZE;
	fat = malloc(fat_alloc_size);
	if (!fat) {
		block_disk_close();
    	return -1;
	}

	// Initialize FAT memory to zero
	memset(fat, 0, fat_alloc_size);

	// Read FAT blocks into our FAT array
	for (int i = 0; i < sb.fat_block_count; i++) {
		if (block_read(1 + i, block) < 0) {
			free(fat);
			fat = NULL;
			block_disk_close();
			return -1;
		}
		// Copy the block data to the appropriate position in the FAT array
		memcpy((uint8_t*)fat + i * BLOCK_SIZE, block, BLOCK_SIZE);
	}

	// Validate that FAT[0] is FAT_EOC as per specification
	if (fat[0] != FAT_EOC) {
		free(fat);
		fat = NULL;
		block_disk_close();
		return -1;
	}

	// Read root directory
	if (block_read(sb.root_dir_index, block) < 0) {
		free(fat);
		fat = NULL;
		block_disk_close();
		return -1;
	}
	memcpy(root_dir, block, sizeof(root_dir));

	/* Initialize open_files array */
	memset(open_files, 0, sizeof(open_files));

	mounted = 1;
	return 0;
}

int fs_umount(void)
{
	if (!mounted) {
		return -1;
	}

	//Check if any files are still open
	//If so, cannot unmount
	for (int i = 0; i < FS_OPEN_MAX_COUNT; i++) {
        if (open_files[i].in_use) {
            return -1;
        }
    }

	//Save all changes to disk
	if (write_fat() < 0) {
        return -1;
    }
    
    if (write_root() < 0) {
        return -1;
    }
	
	if (block_disk_close() < 0) {
		return -1;
	}

	if (fat) {
		free(fat);
		fat = NULL;
	}
	
	memset(&sb, 0, sizeof(sb));
	memset(root_dir, 0, sizeof(root_dir));
	memset(open_files, 0, sizeof(open_files));
	mounted = 0;
	
	return 0;
}

int fs_info(void)
{
	if (!mounted) {
		return -1;
	}

	// Count free FAT entries (entries with value 0, excluding entry 0 which is always FAT_EOC)
	int fat_free_count = 0;
	for (int i = 1; i < sb.data_block_count; i++) {
		if (fat[i] == 0) {
			fat_free_count++;
		}
	}

	// Count free root directory entries (entries where first character of filename is NULL)
	int rdir_free_count = 0;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (root_dir[i].filename[0] == '\0') {
			rdir_free_count++;
		}
	}

	// Print filesystem information
	printf("FS Info:\n");
	printf("total_blk_count=%d\n", sb.total_blocks);
	printf("fat_blk_count=%d\n", sb.fat_block_count);
	printf("rdir_blk=%d\n", sb.root_dir_index);
	printf("data_blk=%d\n", sb.data_start_index);
	printf("data_blk_count=%d\n", sb.data_block_count);
	printf("fat_free_ratio=%d/%d\n", fat_free_count, sb.data_block_count);
	printf("rdir_free_ratio=%d/%d\n", rdir_free_count, FS_FILE_MAX_COUNT);

	return 0;
}

//find_file will return the index of the file, otherwise -1
static int find_file(const char *filename)
{
	if(!filename || strlen(filename) >= FS_FILENAME_LEN) {
		return -1;
	}

	//Just iterate through all files and compare name
	//Return index if match is found
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (strcmp((char*)root_dir[i].filename, filename) == 0) {
            return i;
        }
    }

	//File not found
	return -1;
}

//find_empty_entry will return the index of the first empty entry, otherwise -1
static int find_empty_entry(void)
{
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (root_dir[i].filename[0] == '\0') {
            return i;
        }
    }
    return -1;
}

//write_root creates buffer, puts root directory in buffer, and writes the buffer to disk
//returns 0 on success, otherwise -1
static int write_root(void)
{
	uint8_t block[BLOCK_SIZE];
    memcpy(block, root_dir, sizeof(root_dir));
    return block_write(sb.root_dir_index, block);
}

//write_fat is similar to write_root, as it writes fat to disk
//returns 0 on success, otherwise -1
static int write_fat(void)
{
	uint8_t block[BLOCK_SIZE];
	for (int i = 0; i < sb.fat_block_count; i++) {
    	memcpy(block, (uint8_t*)fat + i * BLOCK_SIZE, BLOCK_SIZE);
        if (block_write(1 + i, block) < 0) {
            return -1;
        }
    }
    
    return 0;
}

//free_fat frees files contents from FAT starting from givne block
static int free_fat(uint16_t first_block)
{
	uint16_t current_block = first_block;
    
    while (current_block != FAT_EOC) {
        if (current_block == 0 || current_block >= sb.data_block_count) {
            return -1; 
		}
        uint16_t next_block = fat[current_block];
        fat[current_block] = 0; 
        current_block = next_block;
    }
    
    return 0;
}

//get_block returns the block given the first block and the offset
static uint16_t get_block(uint16_t first_block, size_t offset)
{
	//If empty file
	if (first_block == FAT_EOC) {
		return FAT_EOC;
	}

	size_t block_number = offset / BLOCK_SIZE;
    uint16_t current_block = first_block;

	//Follow FAT chain to get correct block
	for (size_t i = 0; i < block_number; i++) {
        if (current_block == FAT_EOC || current_block == 0 || current_block >= sb.data_block_count) {
            return FAT_EOC; 
        }
        current_block = fat[current_block];
    }

	return current_block;
}

/* Find free block */
static uint16_t find_free_block(void)
{
	/* Search FAT chain for first free block */
	for (uint16_t i = 1; i < sb.data_block_count; i++) {
		if (fat[i] == 0) {
			return i;
		}
	}
	return FAT_EOC; // nothing was free
}

//is_open compares the root index of open files to given index to see if file is open
//returns 0 if file is open, otherwise -1
static int is_open(int index)
{
	for (int i = 0; i < FS_OPEN_MAX_COUNT; i++) {
        if (open_files[i].in_use && open_files[i].root_index == index) {
            return 0;
        }
    }
    return -1;
}

int fs_create(const char *filename)
{
	if (!mounted || !filename) {
		return -1;
	}

	//If file name is too long
	if (strlen(filename) >= FS_FILENAME_LEN) {
		return -1;
	}

	//If file name already exists
	if (find_file(filename) >= 0) {
		return -1;
	}

	//Find empty entry
	int index = find_empty_entry();
	if (index < 0) {
		return -1;
	}
	
	//Initialize new entry at index
	//Clear entry, set filename, size = 0, first index = FAT_EOC
	memset(&root_dir[index], 0, sizeof(struct root_entry));
	strcpy((char*)root_dir[index].filename, filename);
	root_dir[index].file_size = 0;
	root_dir[index].first_data_block = FAT_EOC;

	//Write to disk
	if (write_root() < 0) {
		return -1;
	}

	return 0;
}

int fs_delete(const char *filename)
{
	if (!mounted || !filename) {
		return -1;
	}

	//If file doesn't exist
	int index = find_file(filename);
	if (index < 0) {
		return -1;
	}
	
	//If file is open
	if (is_open(index) < 0) {
        return -1; 
    }

	//Free data blocks in FAT
	if (root_dir[index].first_data_block != FAT_EOC) {
		if (free_fat(root_dir[index].first_data_block) < 0) {
			return -1;
		}
		
		//Write updated FAT to disk
		if (write_fat() < 0) {
			return -1;
		}
	}

	//free file entry
	memset(&root_dir[index], 0, sizeof(struct root_entry));

	//Write to disk
	if (write_root() < 0) {
        return -1;
    }

	return 0;
}

int fs_ls(void)
{
	if (!mounted) {
		return -1;
	}

	printf("FS Ls:\n");
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (root_dir[i].filename[0] != '\0') {
            printf("file: %s, size: %u, data_blk: %u\n", 
                   root_dir[i].filename, 
                   root_dir[i].file_size, 
                   root_dir[i].first_data_block);
        }
    }

	return 0;
}

int fs_open(const char *filename)
{
	/* Check if mounted */
	if (!mounted || !filename) {
		return -1;
	}

	/* Retreive file from root directory */
	int root_index = find_file(filename);
	if (root_index < 0) {
		return -1; // did not find the file
	}

	/* Secure an unused file descriptor */
	int fd = -1;
	for (int i = 0; i < FS_OPEN_MAX_COUNT; i++) {
		if (!open_files[i].in_use) {
			fd = i;
			break;
		}
	}

	if (fd == -1) {
		return -1; // error if no available file descriptors
	}

	/* Initialize file descriptor */
	open_files[fd].in_use = 1;
	open_files[fd].root_index = root_index;
	open_files[fd].offset = 0;

	return fd;
}

int fs_close(int fd)
{
	/* Check if mounted */
	if (!mounted) {
		return -1;
	}

	/* Validate file descriptor */
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT || !open_files[fd].in_use) {
		return -1;
	}

	/* Reset file descriptor values */
	open_files[fd].in_use = 0;
	open_files[fd].root_index = 0;
	open_files[fd].offset = 0;

	return 0;
}

int fs_stat(int fd)
{
	/* Check if mounted*/
    if (!mounted) {
        return -1;
    }

    /* Validate file descriptor */
    if (fd < 0 || fd >= FS_OPEN_MAX_COUNT || !open_files[fd].in_use) {
        return -1; // Invalid or not open
    }

    /* Get root index */
    int root_index = open_files[fd].root_index;

    /* Return file size */
    return root_dir[root_index].file_size;
}

int fs_lseek(int fd, size_t offset)
{
	/* Check if mounted */
    if (!mounted) {
        return -1;
    }

    /* Validate file descriptor */
    if (fd < 0 || fd >= FS_OPEN_MAX_COUNT || !open_files[fd].in_use) {
        return -1; // Invalid or not open
    }

    /* Get root index */
    int root_index = open_files[fd].root_index;

    /* Make sure offset does not exceed file size */
    if (offset > root_dir[root_index].file_size) {
        return -1;
    }

    /* Update the offset */
    open_files[fd].offset = offset;

    return 0;
}

int fs_write(int fd, void *buf, size_t count)
{
	/* Validate inputs */
    if (!mounted || !buf) {
        return -1;
    }
    if (fd < 0 || fd >= FS_OPEN_MAX_COUNT || !open_files[fd].in_use) {
        return -1;
    }

	/* Get file information */
    int root_index = open_files[fd].root_index;
    size_t current_offset = open_files[fd].offset;
    uint32_t file_size = root_dir[root_index].file_size;
    uint16_t first_block = root_dir[root_index].first_data_block;

	/* Calculate bytes */
    size_t bytes_to_write = count;
    size_t bytes_written = 0;
    uint8_t *buffer = (uint8_t *)buf;
    uint8_t block_buffer[BLOCK_SIZE];

	/* Track last block in chain */
	uint16_t last_block = first_block;
    if (last_block != FAT_EOC) {
        while (fat[last_block] != FAT_EOC && fat[last_block] != 0 && last_block < sb.data_block_count) {
            last_block = fat[last_block];
        }
    }

	while (bytes_written < bytes_to_write) {
        /* Track file position */
        size_t offset_in_file = current_offset + bytes_written;
        size_t offset_in_block = offset_in_file % BLOCK_SIZE;
        size_t bytes_left_in_block = BLOCK_SIZE - offset_in_block;
        size_t bytes_to_write_now = bytes_to_write - bytes_written;
        if (bytes_to_write_now > bytes_left_in_block) {
            bytes_to_write_now = bytes_left_in_block;
        }

        /* Retreive or allocate current block */
        uint16_t data_block = get_block(first_block, offset_in_file);
        if (data_block == FAT_EOC) {
            uint16_t new_block = find_free_block(); // need new block since we hit FAT_EOC
            if (new_block == FAT_EOC) {
                /* No more blocks, update and return */
                if (offset_in_file > file_size) {
                    root_dir[root_index].file_size = offset_in_file;
                    if (write_root() < 0) {
                        return -1;
                    }
                }
                open_files[fd].offset += bytes_written;
                return bytes_written;
            }

            /* Link to new block */
            if (first_block == FAT_EOC) {
                root_dir[root_index].first_data_block = new_block;
                first_block = new_block; // file was empty so we set first to new
            } else {
                fat[last_block] = new_block; // append to chain
            }
            fat[new_block] = FAT_EOC;
            last_block = new_block;
            data_block = new_block;

            /* Write FAT to disk */
            if (write_fat() < 0) {
                return -1;
            }
        }

        uint16_t disk_block = sb.data_start_index + data_block;

        /* Deal with partial writes */
        if (offset_in_block != 0 || bytes_to_write_now < BLOCK_SIZE) {
            /* Read current block to preserve data */
            if (block_read(disk_block, block_buffer) < 0) {
                return -1;
            }
            /* Copy new data into the block */
            memcpy(block_buffer + offset_in_block, buffer + bytes_written, bytes_to_write_now);
            /* Write back the changed block */
            if (block_write(disk_block, block_buffer) < 0) {
                return -1;
            }
        } else {
            /* Write the whole block */
            if (block_write(disk_block, buffer + bytes_written) < 0) {
                return -1;
            }
        }

        bytes_written += bytes_to_write_now;
    }

    /* Update file size */
    if (current_offset + bytes_written > file_size) {
        root_dir[root_index].file_size = current_offset + bytes_written;
        if (write_root() < 0) {
            return -1;
        }
    }

    
    open_files[fd].offset += bytes_written; // update offset

    /* Write modified FAT to disk (if we need to)*/
    if (write_fat() < 0) {
        return -1;
    }

    return bytes_written;
}


int fs_read(int fd, void *buf, size_t count)
{
	if (!mounted || !buf) {
		return -1;
	}

	//If fd is valid
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT || !open_files[fd].in_use) {
		return -1;
	}

	//Get file information
	int root_index = open_files[fd].root_index;
    size_t current_offset = open_files[fd].offset;

	uint32_t file_size = root_dir[root_index].file_size;
    uint16_t first_block = root_dir[root_index].first_data_block;

	//Use file information to calculate # of bytes to read
	size_t bytes_to_read = count;
	//If at end of file
	if (current_offset >= file_size) {
		return 0;
	}
	//If what's left is less than count, read what's left
	if (current_offset + bytes_to_read > file_size) { 
		bytes_to_read = file_size - current_offset;
	}

	size_t bytes_read = 0;
	uint8_t *buffer = (uint8_t *)buf;
    uint8_t block_buffer[BLOCK_SIZE];

	/*  3 Cases:
		1) Partial Block Read
		2) Full Block Read
		3) Multiple Block Read
	*/
	while (bytes_read < bytes_to_read) {
		//Track overall position in file
		size_t offset_in_file = current_offset + bytes_read;
		//Track position within current block
		size_t offset_in_block = offset_in_file % BLOCK_SIZE;
		//Calculate how many more bytes can we read from current block
		size_t bytes_left_in_block = BLOCK_SIZE - offset_in_block;

		//Calculate how many bytes should we read in current iter/block
		//If we have to read more than we can now, read till end of block
		//otherwise, read what we need
		size_t bytes_to_read_now = bytes_to_read - bytes_read;
		if (bytes_to_read_now > bytes_left_in_block) {
			bytes_to_read_now = bytes_left_in_block;
		}

		//Go to the right block
		uint16_t data_block = get_block(first_block, offset_in_file);
		if (data_block == FAT_EOC) {
			break;
		}
		uint16_t disk_block = sb.data_start_index + data_block;

		//Bounce Buffer: Read entire block -> copy into user's buf
		if (block_read(disk_block, block_buffer) < 0) {
            return -1; 
        }
		memcpy(buffer + bytes_read, block_buffer + offset_in_block, bytes_to_read_now);

		//Update counters
		bytes_read += bytes_to_read_now;
	}

	//Update offset
	open_files[fd].offset += bytes_read;

	return (int) bytes_read;
}
