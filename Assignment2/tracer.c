#include <context.h>
#include <memory.h>
#include <lib.h>
#include <entry.h>
#include <file.h>
#include <tracer.h>

#define O_READ 0x1
#define O_WRITE 0x2
#define O_RDWR (O_READ | O_WRITE)

#define MAX_OPEN_FILES 16

int syscall_number_of_arguments(u64 syscall_num)
{
	if (syscall_num == 1)
	{
		return 1; // exit
	}
	else if (syscall_num == 2)
	{
		return 0; // getpid
	}
	else if (syscall_num == 4)
	{
		return 2; // expand
	}
	else if (syscall_num == 5)
	{
		return 0; // shrink
	}
	else if (syscall_num == 6)
	{
		return 0; // alarm
	}
	else if (syscall_num == 7)
	{
		return 1; // sleep
	}
	else if (syscall_num == 8)
	{
		return 2; // signal
	}
	else if (syscall_num == 9)
	{
		return 2; // clone
	}
	else if (syscall_num == 10)
	{
		return 0; // fork
	}
	else if (syscall_num == 11)
	{
		return 0; // stats
	}
	else if (syscall_num == 12)
	{
		return 1; // configure
	}
	else if (syscall_num == 13)
	{
		return 0; // phys_info
	}
	else if (syscall_num == 14)
	{
		return 1; // dump_ptt
	}
	else if (syscall_num == 15)
	{
		return 0; // cfork
	}
	else if (syscall_num == 16)
	{
		return 4; // mmap
	}
	else if (syscall_num == 17)
	{
		return 2; // munmap
	}
	else if (syscall_num == 18)
	{
		return 3; // mprotect
	}
	else if (syscall_num == 19)
	{
		return 1; // pmap
	}
	else if (syscall_num == 20)
	{
		return 0; // vfork
	}
	else if (syscall_num == 21)
	{
		return 0; // get_user_p
	}
	else if (syscall_num == 22)
	{
		return 0; // get_cow_f
	}
	else if (syscall_num == 23)
	{
		return 2; // open
	}
	else if (syscall_num == 24)
	{
		return 3; // read
	}
	else if (syscall_num == 25)
	{
		return 3; // write
	}
	else if (syscall_num == 27)
	{
		return 1; // dup
	}
	else if (syscall_num == 28)
	{
		return 2; // dup2
	}
	else if (syscall_num == 29)
	{
		return 1; // close
	}
	else if (syscall_num == 30)
	{
		return 3; // lseek
	}
	else if (syscall_num == 35)
	{
		return 4; // ftrace
	}
	else if (syscall_num == 36)
	{
		return 1; // trace_buffer
	}
	else if (syscall_num == 37)
	{
		return 2; // start_strace
	}
	else if (syscall_num == 38)
	{
		return 0; // end_strace
	}
	else if (syscall_num == 39)
	{
		return 3; // read_strace
	}
	else if (syscall_num == 40)
	{
		return 2; // strace
	}
	else if (syscall_num == 41)
	{
		return 3; // read_ftrace
	}
	else if (syscall_num == 61)
	{
		return 1; // getppid
	}
	else
	{
		return -1; // Invalid syscall number
	}
}

///////////////////////////////////////////////////////////////////////////
//// 		        Start of Trace buffer functionality 		      /////
///////////////////////////////////////////////////////////////////////////

int is_valid_mem_range(unsigned long buff, u32 count, int access_bit)
{
	// Get the current process's execution context.
	struct exec_context *pcb_current = get_current_ctx();

	// Get the memory segment information for the current process.
	struct mm_segment *mms_current = pcb_current->mms;

	// Check if the memory buffer falls within the code segment.
	if (mms_current[MM_SEG_CODE].start <= buff && buff < mms_current[MM_SEG_STACK].end)
	{
		// Check if the buffer is within the code segment and has appropriate access permissions.
		if (mms_current[MM_SEG_CODE].start <= buff && buff < mms_current[MM_SEG_CODE].next_free)
		{
			// If access_bit is 0 (read), return 0 to indicate invalid access.
			if (access_bit == 0)
				return 0;
		}

		// Check if the buffer is within the read-only data segment and has appropriate access permissions.
		if (mms_current[MM_SEG_RODATA].start <= buff && buff < mms_current[MM_SEG_RODATA].next_free)
		{
			// If access_bit is 0 (read), return 0 to indicate invalid access.
			if (access_bit == 0)
				return 0;
		}

		// Return 1 to indicate valid memory access within the code segment.
		return 1;
	}

	// Get the virtual memory area information for the current process.
	struct vm_area *vm_current = pcb_current->vm_area;

	// Iterate through the virtual memory areas to check memory access.
	while (vm_current != NULL)
	{
		if (vm_current->vm_start <= buff && buff <= vm_current->vm_end)
		{
			// Check if the buffer falls within a virtual memory area and has the correct access permissions.
			if (access_bit == vm_current->access_flags - 1)
				return 0;
		}
		vm_current = vm_current->vm_next;
	}

	// Return 1 to indicate valid memory access within the virtual memory areas.
	return 1;
}

long trace_buffer_close(struct file *filep)
{
	// Get the current process's execution context.
	struct exec_context *pcb_current = get_current_ctx();

	// Get the file descriptor from the trace buffer.
	int fd = filep->trace_buffer->fd;

	// Free the memory allocated for the trace buffer.
	os_page_free(USER_REG, filep->trace_buffer->buffer);

	// Free memory allocated for the trace buffer info structure.
	os_free(filep->trace_buffer, sizeof(struct trace_buffer_info));

	// Free memory allocated for the file operations structure.
	os_free(filep->fops, sizeof(struct fileops));

	// Free memory allocated for the file structure.
	os_free(filep, sizeof(struct file));

	// Set the file descriptor entry in the current process to NULL.
	pcb_current->files[fd] = NULL;

	return 0;
}

int trace_buffer_read(struct file *filep, char *buff, u32 count)
{
	// Check if the file is in write mode and return an error if so.
	if (filep->mode == O_WRITE)
		return -EINVAL;

	// Valid memory check - Comment out for subpart 2 of question 1.
	// unsigned long buff_addr = (unsigned long) &buff[0];
	// if (!is_valid_mem_range(buff_addr, count, 0)) return -EBADMEM;

	// Get the trace buffer information from the file.
	struct trace_buffer_info *curr_trace_buffer = filep->trace_buffer;
	int write_offset = curr_trace_buffer->write_offset_tb;
	int read_offset = curr_trace_buffer->read_offset_tb;
	char *head_p = curr_trace_buffer->buffer;
	int write_flag = 0;
	int count_read = 0;
	int index = read_offset;

	// Check if there's no more space for reading in the buffer.
	if (curr_trace_buffer->reading_space_left == 0)
		return 0;

	// Check if there's nothing to read.
	if (count == 0)
	{
		return 0;
	}

	// If both the write and read offsets are at the beginning, read the first character.
	if (write_offset == 0 && read_offset == 0)
	{
		buff[0] = head_p[index];
		index++;
		count_read++;
	}

	while (index < 4096 && index - read_offset < count)
	{
		// Check if the write offset is reached.
		if (index == write_offset)
		{
			write_flag = 1;
			break;
		}

		// Read characters from the trace buffer to the buffer.
		buff[index - read_offset] = head_p[index];
		count_read++;
		index++;
	}
	curr_trace_buffer->read_offset_tb = index;

	int read_check = count_read;

	// If not all data was read and there's no write flag, continue reading.
	if (!write_flag && count_read < count)
	{
		index = 0;
		while (index != write_offset && count_read < count)
		{
			buff[read_check + index] = head_p[index];
			count_read++;
			index++;
		}

		// Update the read offset again.
		curr_trace_buffer->read_offset_tb = index;
	}

	// If the read offset reaches the end, reset it.
	if (curr_trace_buffer->read_offset_tb >= 4096)
	{
		curr_trace_buffer->read_offset_tb %= 4096;
	}

	// Update the space left for reading and writing.
	curr_trace_buffer->reading_space_left -= count_read;
	curr_trace_buffer->writing_space_left = 4096 - curr_trace_buffer->reading_space_left;

	return count_read;
}

int trace_buffer_write(struct file *filep, char *buffer, u32 count)
{
	// Check if the file is in read mode, and return an error if so.
	if (filep->mode == O_READ)
		return -EINVAL;

	// Valid memory check - Comment out for subpart 2 of question 1.
	// unsigned long buffer_addr = (unsigned long) &buffer[0];
	// if (!is_valid_mem_range((unsigned long) buffer, count, 1)) return -EBADMEM;

	// Get the trace buffer information from the file.
	struct trace_buffer_info *curr_trace_buffer = filep->trace_buffer;
	int write_offset = curr_trace_buffer->write_offset_tb;
	int read_offset = curr_trace_buffer->read_offset_tb;
	char *head_p = curr_trace_buffer->buffer;
	int is_reading = 0;
	int bytes_written = 0;
	int write_index = write_offset;

	// Check if there's no more space for writing in the buffer.
	if (curr_trace_buffer->writing_space_left == 0)
	{
		return 0;
	}

	// Check if there's nothing to write.
	if (count == 0)
	{
		return 0;
	}

	// Write the first character from the buffer.
	head_p[write_index] = buffer[0];
	write_index++;
	bytes_written++;

	while (write_index < 4096 && (write_index - write_offset) < count)
	{
		// Check if the read offset is reached.
		if (write_index == read_offset)
		{
			is_reading = 1;
			break;
		}

		// Write characters from the buffer to the trace buffer.
		head_p[write_index] = buffer[write_index - write_offset];
		bytes_written++;
		write_index++;
	}

	// Update the write offset.
	curr_trace_buffer->write_offset_tb = write_index;

	int write_check = write_index;

	// If not all data was written and there's no read flag, continue writing.
	if (!is_reading && bytes_written < count)
	{
		write_index = 0;
		while (write_index != read_offset && bytes_written < count)
		{
			head_p[write_index] = buffer[write_check - write_offset + write_index];
			bytes_written++;
			write_index++;
		}

		// Update the write offset again.
		curr_trace_buffer->write_offset_tb = write_index;
	}

	// If the write offset reaches the end, reset it.
	if (curr_trace_buffer->write_offset_tb >= 4096)
	{
		curr_trace_buffer->write_offset_tb %= 4096;
	}
	// Update the space left for writing and reading.
	curr_trace_buffer->writing_space_left -= bytes_written;
	curr_trace_buffer->reading_space_left = 4096 - curr_trace_buffer->writing_space_left;

	return bytes_written;
}

// Create a trace buffer for the current process.
int sys_create_trace_buffer(struct exec_context *current, int mode)
{
	int fd = -1; // Initialize the file descriptor.

	// Allocate memory for a new file structure.
	struct file *new_file = os_alloc(sizeof(struct file));

	// Get the file descriptor table associated with the current process.
	struct file **file_descriptor_table = current->files;

	// Find the lowest available file descriptor.
	for (int i = 0; i < MAX_OPEN_FILES; i++)
	{
		if (file_descriptor_table[i] == NULL)
		{
			fd = i;
			file_descriptor_table[i] = new_file;
			break;
		}
	}

	if (fd == -1)
		return -EINVAL; // Return an error if no available file descriptor was is_found.

	new_file->type = TRACE_BUFFER;
	new_file->mode = mode;
	new_file->offp = 0;
	new_file->inode = NULL;

	// Allocate memory for trace buffer information.
	struct trace_buffer_info *curr_trace_buffer = os_alloc(sizeof(struct trace_buffer_info));

	// Initialize trace buffer attributes.
	curr_trace_buffer->fd = fd;
	curr_trace_buffer->buffer = (char *)os_page_alloc(USER_REG);
	curr_trace_buffer->write_offset_tb = 0;
	curr_trace_buffer->read_offset_tb = 0;
	curr_trace_buffer->reading_space_left = 0;
	curr_trace_buffer->writing_space_left = 4096;

	new_file->trace_buffer = curr_trace_buffer;

	// Allocate memory for file operations.
	struct fileops *new_file_ops = os_alloc(sizeof(struct fileops));

	// Assign file operation functions.
	new_file_ops->read = trace_buffer_read;
	new_file_ops->write = trace_buffer_write;
	new_file_ops->close = trace_buffer_close;
	new_file->fops = new_file_ops;

	return fd; // Return the created file descriptor.
}

///////////////////////////////////////////////////////////////////////////
//// 	        	Start of strace functionality 		      	      /////
///////////////////////////////////////////////////////////////////////////

int perform_tracing(u64 syscall_num, u64 param1, u64 param2, u64 param3, u64 param4)
{
	// Get the current execution context
	struct exec_context *pcb_current = get_current_ctx();

	// Get the strace metadata head from the current context
	struct strace_head *base_head = pcb_current->st_md_base;

	// If the strace metadata head is not initialized, create and initialize it
	if (base_head == NULL)
	{
		base_head = os_alloc(sizeof(struct strace_head));
		base_head->count = 0;
		base_head->strace_fd = 0;
		base_head->is_traced = 0;
		base_head->next = NULL;
		base_head->last = NULL;

		// Set the strace metadata head in the current context
		pcb_current->st_md_base = base_head;
		return 0;
	}

	// Check if tracing is disabled or if the syscall is "end_strace"
	if (base_head->is_traced == 0 || syscall_num == 38)
	{
		return 0;
	}

	// If tracing is in filtered mode, check if the syscall should be traced
	if (base_head->tracing_mode == FILTERED_TRACING)
	{
		int flag = 0;
		struct strace_info *info_ptr = base_head->next;

		// Iterate through strace info to find the syscall to trace
		while (info_ptr != NULL)
		{
			if (info_ptr->syscall_num == syscall_num)
			{
				flag = 1;
				break;
			}
			info_ptr = info_ptr->next;
		}

		// If the syscall is not in the list of traced syscalls, skip tracing
		if (flag == 0)
			return 0;
	}

	// Get the file descriptor associated with the strace
	int fd = base_head->strace_fd;

	// Get the trace buffer info from the file descriptor
	struct trace_buffer_info *curr_trace_buffer = pcb_current->files[fd]->trace_buffer;
	struct file *filep = pcb_current->files[fd];

	u64 end = -1;

	// Determine the number of arguments for the syscall
	int num_args = syscall_number_of_arguments(syscall_num);

	// Write the syscall number to the trace buffer
	int ret = trace_buffer_write(filep, &syscall_num, 8);

	// Write syscall arguments to the trace buffer based on the number of arguments
	if (num_args == 1)
	{
		ret = trace_buffer_write(filep, &param1, 8);
	}

	if (num_args == 2)
	{
		ret = trace_buffer_write(filep, &param1, 8);
		ret = trace_buffer_write(filep, &param2, 8);
	}
	if (num_args == 3)
	{
		ret = trace_buffer_write(filep, &param1, 8);
		ret = trace_buffer_write(filep, &param2, 8);
		ret = trace_buffer_write(filep, &param3, 8);
	}
	if (num_args == 4)
	{
		ret = trace_buffer_write(filep, &param1, 8);
		ret = trace_buffer_write(filep, &param2, 8);
		ret = trace_buffer_write(filep, &param3, 8);
		ret = trace_buffer_write(filep, &param4, 8);
	}

	// Write metadata to the trace buffer
	u64 meta_data = 0;
	ret = trace_buffer_write(filep, &meta_data, 8);

	return 0;
}

int sys_strace(struct exec_context *current, int syscall_num, int action)
{
	// Get the strace metadata head from the current execution context
	struct strace_head *base_head = current->st_md_base;

	// If the action is to add a syscall to strace
	if (action == ADD_STRACE)
	{
		// Initialize a new strace info structure
		struct strace_info *info_ptr = base_head->last;
		struct strace_info *new_info = os_alloc(sizeof(struct strace_info));
		new_info->syscall_num = syscall_num;
		new_info->next = NULL;

		// Check if the info_ptr is NULL
		if (!info_ptr)
		{
			// If info_ptr is NULL, set the new_info as both next and last
			base_head->next = new_info;
			base_head->last = new_info;
		}
		else
		{
			// If info_ptr is not NULL, update the last pointer and link the new_info
			base_head->last->next = new_info;
			base_head->last = new_info;
		}
	}
	else
	{
		// If the action is to remove a syscall from strace
		if (base_head->next == base_head->last && base_head->next->syscall_num == syscall_num)
		{
			// If there is only one element and it matches the syscall_num, remove it
			os_free(base_head->next, sizeof(struct strace_info));
			base_head->next = NULL;
			base_head->last = NULL;
		}

		// Initialize info_ptr to the start of the list
		struct strace_info *info_ptr = base_head->next;
		while (info_ptr && info_ptr != base_head->last)
		{
			// Find the matching syscall_num and remove it
			if (info_ptr->next->syscall_num == syscall_num)
			{
				struct strace_info *info_ptr = info_ptr->next;
				info_ptr->next == info_ptr->next->next;
				os_free(info_ptr, sizeof(struct strace_info));
				break;
			}
		}

		// Update last pointer if the next of info_ptr is NULL
		if (info_ptr->next == NULL)
		{
			base_head->last = info_ptr;
		}

		// Check if the first element matches the syscall_num and remove it
		if (base_head->next->syscall_num == syscall_num)
		{
			struct strace_info *info_ptr = base_head->next;
			base_head->next = base_head->next->next;
			os_free(info_ptr, sizeof(struct strace_info));
		}
	}

	return 0;
}

int sys_read_strace(struct file *filep, char *buff, u64 count)
{
	// Check if the count is zero, and return 0 bytes read if so
	if (count == 0)
		return 0;

	int write_offset = 0; // Initialize the write offset to 0
	int ret, num_args;	  // Initialize return value and number of arguments
	u64 syscall_num;	  // Variable to store the syscall number

	while (count > 0)
	{
		// Read the syscall number from the trace buffer
		ret = trace_buffer_read(filep, &syscall_num, 8);

		// If no data was read, return the current write offset
		if (ret == 0)
		{
			return write_offset;
		}

		// Determine the number of arguments for the syscall
		num_args = syscall_number_of_arguments(syscall_num);

		// Extract and copy the bytes of the syscall number to the buffer
		for (int i = 0; i < 8; i++)
		{
			char byte = (syscall_num >> (i * 8)) & 0xFF;
			buff[write_offset + i] = byte;
		}
		write_offset += 8; // Increment the write offset

		// Read the remaining data (arguments) from the trace buffer
		ret = trace_buffer_read(filep, buff + write_offset, num_args * 8 + 8);
		write_offset += 8 * num_args; // Increment the write offset by the size of the arguments
		count--;					  // Decrement the count of bytes remaining to read
	}

	// Return the total number of bytes read
	return write_offset;
}

int sys_start_strace(struct exec_context *current, int fd, int tracing_mode)
{
	// Get the strace metadata from the current process context
	struct strace_head *base_head = current->st_md_base;

	// Reset the count of traced syscalls to zero
	base_head->count = 0;

	// Enable tracing for the current process
	base_head->is_traced = 1;

	// Set the strace file descriptor for the process
	base_head->strace_fd = fd;

	// Set the tracing mode based on the provided value
	base_head->tracing_mode = tracing_mode;

	// Return 0 to indicate successful start of strace
	return 0;
}

int sys_end_strace(struct exec_context *current)
{
	// Get the strace metadata from the current process context
	struct strace_head *base_head = current->st_md_base;

	// Disable tracing for the current process
	base_head->is_traced = 0;

	// Initialize a pointer to the first traced syscall information
	struct strace_info *info_ptr = base_head->next;

	// Initialize a temporary pointer to help with freeing memory
	struct strace_info *temp_ptr;

	// Iterate through traced syscall information and free memory
	while (info_ptr != base_head->last)
	{
		// Store the next syscall information pointer
		temp_ptr = info_ptr->next;

		// Free the current syscall information
		os_free(info_ptr, sizeof(struct strace_info));

		// Move to the next syscall information
		info_ptr = temp_ptr;
	}

	// Free the last traced syscall information
	os_free(base_head->last, sizeof(struct strace_info));

	// Return 0 to indicate successful end of strace
	return 0;
}

///////////////////////////////////////////////////////////////////////////
//// 		Start of ftrace functionality 		      	      /////
///////////////////////////////////////////////////////////////////////////

long do_ftrace(struct exec_context *current, unsigned long faddr, long action, long num_args, int fd_trace_buffer)
{
	// Check if the process's function tracing metadata is initialized
	if (current->ft_md_base == NULL)
	{
		// If not initialized, allocate memory and initialize it
		current->ft_md_base = os_alloc(sizeof(struct ftrace_head));
		current->ft_md_base->next = NULL;
		current->ft_md_base->last = NULL;
		current->ft_md_base->count = 0;
	}

	if (action == ADD_FTRACE)
	{
		// Check if the maximum allowed function traces have been reached
		if (current->st_md_base->count > FTRACE_MAX)
		{
			return -EINVAL; // Return an error code (-EINVAL) if the limit is exceeded
		}

		// Iterate through existing ftrace_info entries to check for duplicates
		struct ftrace_info *info_ptr = current->ft_md_base->next;
		while (info_ptr != NULL)
		{
			if (info_ptr->faddr == faddr)
			{
				return -EINVAL; // Return an error code (-EINVAL) if a duplicate ftrace request is found
			}
			info_ptr = info_ptr->next;
		}

		// Allocate memory and create a new ftrace_info entry
		struct ftrace_info *new = os_alloc(sizeof(struct ftrace_info));
		new->faddr = faddr;
		new->num_args = num_args;
		new->fd = fd_trace_buffer;
		new->capture_backtrace = 0; // Initialize capture_backtrace to 0
		new->next = NULL;

		// Add the new entry to the linked list
		if (current->ft_md_base->last != NULL)
		{
			current->ft_md_base->last->next = new;
		}
		current->ft_md_base->last = new;

		if (current->ft_md_base->next == NULL)
		{
			current->ft_md_base->next = new;
		}

		current->ft_md_base->count++; // Increment the count of function traces
	}
	else if (action == REMOVE_FTRACE)
	{
		int valid = 0;
		// Iterate through existing ftrace_info entries
		struct ftrace_info *info_ptr = current->ft_md_base->next;
		while (info_ptr != NULL)
		{
			if (info_ptr->faddr == faddr)
			{
				valid = 1;
				struct ftrace_info *ptr_next_1 = current->ft_md_base->next;
				while (ptr_next_1 != NULL)
				{
					if (ptr_next_1->next == info_ptr)
						break;
					ptr_next_1 = ptr_next_1->next;
				}
				struct ftrace_info *ptr_next_2 = info_ptr->next;

				if (ptr_next_1 == NULL)
					current->ft_md_base->next = ptr_next_2;
				else
					ptr_next_1->next = ptr_next_2;

				os_free(info_ptr, sizeof(struct ftrace_info));
				current->ft_md_base->count--; // Decrement the count of function traces
			}
			info_ptr = info_ptr->next;
		}
		if (!valid)
		{
			return -EINVAL; // Return an error code (-EINVAL) if the requested ftrace is not found
		}
	}
	else if (action == ENABLE_FTRACE)
	{
		// Enabling function tracing for a specific function address
		struct ftrace_info *info_ptr = current->ft_md_base->next;
		int is_found = 0;

		while (info_ptr != NULL)
		{
			if (info_ptr->faddr == faddr)
			{
				u8 *faddr_ptr = (u8 *)faddr;

				// Backup the original function code (4 bytes)
				for (int i = 0; i < 4; i++)
				{
					info_ptr->code_backup[i] = *(faddr_ptr + i);
				}

				// Modify the function code with the "INV_OPCODE"
				for (int i = 0; i < 4; i++)
				{
					*(faddr_ptr + i) = (INV_OPCODE);
				}
				is_found = 1;
				break;
			}

			info_ptr = info_ptr->next;
		}
		if (!is_found)
			return -EINVAL; // Return an error code (-EINVAL) if the requested function is not found
	}
	else if (action == DISABLE_FTRACE)
	{
		// Disabling function tracing for a specific function address
		struct ftrace_info *info_ptr = current->ft_md_base->next;
		int is_found = 0;
		while (info_ptr != NULL)
		{
			if (info_ptr->faddr == faddr)
			{
				u8 *faddr_ptr = (u8 *)faddr;

				// Restore the original function code from the backup
				for (int i = 0; i < 4; i++)
				{
					*(faddr_ptr + i) = info_ptr->code_backup[i];
				}
				is_found = 1;
				break;
			}

			info_ptr = info_ptr->next;
		}
		if (!is_found)
			return -EINVAL; // Return an error code (-EINVAL) if the requested function is not found
	}
	else if (action == ENABLE_BACKTRACE)
	{
		// Enabling function tracing with backtrace capture for a specific function address
		struct ftrace_info *info_ptr = current->ft_md_base->next;
		int is_found = 0;
		while (info_ptr != NULL)
		{
			if (info_ptr->faddr == faddr)
			{
				u8 *faddr_ptr = (u8 *)faddr;

				// Backup the original function code (4 bytes)
				for (int i = 0; i < 4; i++)
				{
					info_ptr->code_backup[i] = *(faddr_ptr + i);
				}

				// Modify the function code with the "INV_OPCODE"
				for (int i = 0; i < 4; i++)
				{
					*(faddr_ptr + i) = (INV_OPCODE);
				}
				info_ptr->capture_backtrace = 1; // Enable backtrace capture
				is_found = 1;
				break;
			}
			info_ptr = info_ptr->next;
		}
		if (!is_found)
			return -EINVAL; // Return an error code (-EINVAL) if the requested function is not found
	}
	else if (action == DISABLE_BACKTRACE)
	{
		// Disabling backtrace capture for a specific function address
		struct ftrace_info *info_ptr = current->ft_md_base->next;
		int is_found = 0;
		while (info_ptr != NULL)
		{
			if (info_ptr->faddr == faddr)
			{
				u8 *faddr_ptr = (u8 *)faddr;

				// Restore the original function code from the backup
				for (int i = 0; i < 4; i++)
				{
					*(faddr_ptr + i) = info_ptr->code_backup[i];
				}
				info_ptr->capture_backtrace = 0; // Disable backtrace capture
				is_found = 1;
				break;
			}
			info_ptr = info_ptr->next;
		}
		if (!is_found)
			return -EINVAL; // Return an error code if the requested function is not found
	}
	return 0; // Return success after performing the specified action
}

long handle_ftrace_fault(struct user_regs *regs)
{
	struct exec_context *pcb_current = get_current_ctx();
	struct ftrace_info *info_ptr = pcb_current->ft_md_base->next;
	struct ftrace_info *ftrace_current = NULL;
	long fd = -1;

	// Search for a matching function address in the linked list
	while (info_ptr)
	{
		if (info_ptr->faddr == regs->entry_rip)
		{
			ftrace_current = info_ptr;
			fd = info_ptr->fd;
			break;
		}
		info_ptr = info_ptr->next;
	}

	// If no matching ftrace info is is_found, return an error code
	if (info_ptr == NULL)
		return -EINVAL; // Return an error code (-EINVAL) if no matching ftrace info is is_found

	int num_args = ftrace_current->num_args;
	struct file *filep = pcb_current->files[ftrace_current->fd];
	u64 delemiter = num_args;

	// Check if capturing a backtrace is required
	if (ftrace_current->capture_backtrace)
	{
		delemiter++;
		u64 return_address = *(u64 *)regs->entry_rsp;
		u64 rbp = regs->rbp;

		// Capture the return addresses and update the delimiter
		while (return_address != END_ADDR)
		{
			delemiter++;
			return_address = *(u64 *)(rbp + 8);
			rbp = *(u64 *)rbp;
		}
	}

	delemiter++;

	struct file *trace_buff = pcb_current->files[fd];

	// Write the delimiter to the trace buffer
	*(u64 *)(trace_buff->trace_buffer->buffer + trace_buff->trace_buffer->write_offset_tb) = delemiter;
	trace_buff->trace_buffer->write_offset_tb = (trace_buff->trace_buffer->write_offset_tb + sizeof(u64)) % TRACE_BUFFER_MAX_SIZE;
	trace_buff->trace_buffer->writing_space_left -= sizeof(u64);

	// Write the faddr (function address) to the trace buffer
	*(u64 *)(trace_buff->trace_buffer->buffer + trace_buff->trace_buffer->write_offset_tb) = ftrace_current->faddr;
	trace_buff->trace_buffer->write_offset_tb = (trace_buff->trace_buffer->write_offset_tb + sizeof(u64)) % TRACE_BUFFER_MAX_SIZE;
	trace_buff->trace_buffer->writing_space_left -= sizeof(u64);

	// Write arguments to the trace buffer based on the number of arguments (num_args)
	if (num_args >= 1)
	{
		*(u64 *)(trace_buff->trace_buffer->buffer + trace_buff->trace_buffer->write_offset_tb) = regs->rdi;
		trace_buff->trace_buffer->write_offset_tb = (trace_buff->trace_buffer->write_offset_tb + sizeof(u64)) % TRACE_BUFFER_MAX_SIZE;
		trace_buff->trace_buffer->writing_space_left -= sizeof(u64);
	}

	if (num_args >= 2)
	{
		*(u64 *)(trace_buff->trace_buffer->buffer + trace_buff->trace_buffer->write_offset_tb) = regs->rsi;
		trace_buff->trace_buffer->write_offset_tb = (trace_buff->trace_buffer->write_offset_tb + sizeof(u64)) % TRACE_BUFFER_MAX_SIZE;
		trace_buff->trace_buffer->writing_space_left -= sizeof(u64);
	}

	if (num_args >= 3)
	{
		*(u64 *)(trace_buff->trace_buffer->buffer + trace_buff->trace_buffer->write_offset_tb) = regs->rdx;
		trace_buff->trace_buffer->write_offset_tb = (trace_buff->trace_buffer->write_offset_tb + sizeof(u64)) % TRACE_BUFFER_MAX_SIZE;
		trace_buff->trace_buffer->writing_space_left -= sizeof(u64);
	}

	if (num_args >= 4)
	{
		*(u64 *)(trace_buff->trace_buffer->buffer + trace_buff->trace_buffer->write_offset_tb) = regs->rcx;
		trace_buff->trace_buffer->write_offset_tb = (trace_buff->trace_buffer->write_offset_tb + sizeof(u64)) % TRACE_BUFFER_MAX_SIZE;
		trace_buff->trace_buffer->writing_space_left -= sizeof(u64);
	}

	if (num_args >= 5)
	{
		*(u64 *)(trace_buff->trace_buffer->buffer + trace_buff->trace_buffer->write_offset_tb) = regs->r8;
		trace_buff->trace_buffer->write_offset_tb = (trace_buff->trace_buffer->write_offset_tb + sizeof(u64)) % TRACE_BUFFER_MAX_SIZE;
		trace_buff->trace_buffer->writing_space_left -= sizeof(u64);
	}

	// Check if backtrace capture is required and capture the backtrace
	if (ftrace_current->capture_backtrace)
	{
		*(u64 *)(trace_buff->trace_buffer->buffer + trace_buff->trace_buffer->write_offset_tb) = ftrace_current->faddr;
		trace_buff->trace_buffer->write_offset_tb = (trace_buff->trace_buffer->write_offset_tb + sizeof(u64)) % TRACE_BUFFER_MAX_SIZE;
		trace_buff->trace_buffer->writing_space_left -= sizeof(u64);

		u64 return_address = *(u64 *)regs->entry_rsp;
		u64 rbp = regs->rbp;

		// Capture the return addresses of the backtrace
		while (return_address != END_ADDR)
		{
			*(u64 *)(trace_buff->trace_buffer->buffer + trace_buff->trace_buffer->write_offset_tb) = return_address;
			trace_buff->trace_buffer->write_offset_tb = (trace_buff->trace_buffer->write_offset_tb + sizeof(u64)) % TRACE_BUFFER_MAX_SIZE;
			trace_buff->trace_buffer->writing_space_left -= sizeof(u64);
			return_address = *(u64 *)(rbp + 8);
			rbp = *(u64 *)rbp;
		}
	}

	// Update the registers
	regs->entry_rsp -= 8;
	*((u64 *)regs->entry_rsp) = regs->rbp;
	regs->rbp = regs->entry_rsp;
	regs->entry_rip += 4;

	return 0;
}

int sys_read_ftrace(struct file *filep, char *buff, u64 count)
{
	// Check for invalid input conditions
	if (buff == NULL || filep == NULL || filep->type != TRACE_BUFFER || filep->trace_buffer == NULL)
	{
		return -EINVAL; // Return an error code (-EINVAL) for invalid input
	}

	int bytes = 0;			   // Initialize the number of bytes read
	u64 num_of_parameters;	   // Variable to store the number of parameters in a trace entry
	u64 parameters_array[550]; // Array to store the parameters in a trace entry

	// Loop until 'count' bytes have been read or the trace buffer is full
	for (int i = 0; i < count && filep->trace_buffer->writing_space_left != 4096; i++)
	{
		// Read the number of parameters from the trace buffer
		num_of_parameters = *(u64 *)(filep->trace_buffer->buffer + filep->trace_buffer->read_offset_tb);

		// Loop through the parameters and store them in 'parameters_array'
		for (int j = 1; j <= num_of_parameters; j++)
		{
			parameters_array[j - 1] = *(u64 *)(filep->trace_buffer->buffer + filep->trace_buffer->read_offset_tb + j * sizeof(u64));
		}

		// Update the read offset and available writing space in the trace buffer
		filep->trace_buffer->read_offset_tb = (filep->trace_buffer->read_offset_tb + (num_of_parameters + 1) * sizeof(u64)) % TRACE_BUFFER_MAX_SIZE;
		filep->trace_buffer->writing_space_left = filep->trace_buffer->writing_space_left + (num_of_parameters + 1) * sizeof(u64);

		// Copy the parameters to 'buff'
		for (int j = 0; j < num_of_parameters; j++)
		{
			*(u64 *)(buff + j * sizeof(u64)) = parameters_array[j];
		}

		// Update 'buff', 'bytes', and 'count'
		buff = buff + (num_of_parameters) * sizeof(u64);
		bytes += (num_of_parameters) * sizeof(u64);
	}

	// Return the total number of bytes read
	return bytes;
}
