#!/bin/bash

#Check, download and install the required command dependencies 

#Formatting - pure aesthetic purposes
function display_separator() {
	local separator_length=60
	local separator_char="="
	local color_code="\033[1;34m" # Blue color (change color code as needed)
	local reset_code="\033[0m"   # Reset formatting
	
	printf "${color_code}%s${reset_code}\n" "$(printf "%${separator_length}s" | tr ' ' "$separator_char")"
}

#1. Getting the User Input
#Formatting
echo -e "\033[1;33mStage 1: Getting the User Input\033[0m" 
display_separator

##1.1 Get from the user a network to scan.
ipaddr=""
while true; do
	#Requests for the ip address input to scan
	read -p 'Welcome Pentester, please enter a network (IP address) to scan: ' ipaddr_input

	#Validation check with bash regex to ensure that only IP addressess are entered 
	#Checks for 4 occuring 3 sequential digits separated by a dot (Creds: https://ioflood.com/blog/bash-regex/)
	if ! [[ $ipaddr_input =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then 
		echo -e 'Invalid IP address entered. Please try again!\n'
	else
		ipaddr=$ipaddr_input
		break
	fi
done

##1.2 Get from the user a name for the output directory.
chosen_dir=""
while true; do
	exit_loop=false 
	read -p 'Name the directory you want to save in: ' dir_input
	
	#Checks if the directory exists (Creds: https://tldp.org/LDP/abs/html/fto.html)
	if [ ! -d "$dir_input" ]; then
	
	#If directory does not exist, suggest all close name-related directory in a list, then convert the string results into array.
		echo -e '\nThe directory you have entered does not exist.'
		echo 'Searching for similar directories...'
		mapfile -t matching_dirs < <(sudo find / -type d -name "*$dir_input*" 2>/dev/null)
	
	#If there are no directories found, ask user for another directory (Creds: https://tldp.org/LDP/abs/html/arrays.html#EX66)
		if [ ${#matching_dirs[@]} -eq 0 ]; then
			echo -e '\nNo directories were found. Please enter a different directory.'
			continue
			
		else
	#Display the numbered list of matching directories
			echo -e ' \nDirectories found:'
			for ((i=0; i<${#matching_dirs[@]}; i++)); do
				echo "$((i+1)). ${matching_dirs[i]}"
			done
			echo -e "\nEnter 'exit' to return to the previous menu\n"

	#Allow users to pick directory based on searched results
			while true; do
				read -p 'Select the directory (number): ' dir_num
				dir_index=$((dir_num-1))
					
	#Validation range check of the list of directories
				if [ $dir_index -ge 0 ] && [ $dir_index -lt ${#matching_dirs[@]} ]; then
					selected_dir="${matching_dirs[dir_index]}"
					echo "Selected directory: $selected_dir"
					chosen_dir=$selected_dir
					echo "Directory saved!"
					break
					
				elif [ "$dir_num" = "exit" ]; then
					exit_loop=true
					break

				else
					echo -e 'Invalid selection. Please try again.\n'
					continue
			
				fi
			done
		fi
		
	#This serves to exit the first while loop to return to the previous menu
		if [ "$exit_loop" = "true" ]; then
			continue
		else
			break
		fi		
	else
		chosen_dir=$dir_input
		echo "Directory saved!"
		break
	fi
done


#Function to save output to log file
function save_to_log() {
    local log_file="$1"
    shift
    echo "$@" >> "${chosen_dir}/${log_file}"
}

#2. Weak Credentials	
function hydrascan()
##2.1 Look for weak passwords used in the network for login services.
{
	while true; do
		#Display prompt and gather username list
		read -p "Enter the path to the username list: " username_list
	
		#Validate if the file exists and has a compatible extension (.lst or .txt)
		if [ -f "$username_list" ] && [[ "$username_list" == *.lst || "$username_list" == *.txt ]]; then
			break  # Valid file, exit the loop
		else
			echo "Invalid username list. File must exist and have a .lst or .txt extension."
		fi
	done

###2.1.1 Have a built-in password.lst to check for weak passwords.
###2.1.2 Allow the user to supply their own password list.
    #Check if user wants to use a built-in password list
    internal_passwords=("123456" "12345678" "123456789" "12345" "1234567" "password" "1password" "abc123" "qwerty" "111111" "1234" "iloveyou" "sunshine" "monkey" "1234567890" "123123" "princess" "baseball" "dragon" "football" "shadow" "soccer" "unknown" "000000" "myspace1" "purple" "fuckyou" "superman" "Tigger" "buster" "pepper" "ginger" "qwerty123" "qwerty1" "peanut" "summer" "654321" "michael1" "cookie" "LinkedIn" "whatever" "mustang" "qwertyuiop" "123456a" "123abc" "letmein" "freedom" "basketball" "babygirl" "hello" "qwe123" "fuckyou1" "love" "family" "yellow" "trustno1" "jesus1" "chicken" "diamond" "scooter" "booboo" "welcome" "smokey" "cheese" "computer" "butterfly" "696969" "midnight" "princess1" "orange" "monkey1" "killer" "snoopy" "qwerty12" "1qaz2wsx" "bandit" "sparky" "666666" "football1" "master" "asshole" "batman" "sunshine1" "bubbles" "friends" "1q2w3e4r" "chocolate" "Yankees" "Tinkerbell" "iloveyou1" "abcd1234" "flower" "121212" "passw0rd" "pokemon" "StarWars" "iloveyou2" "123qwe" "Pussy" "angel1" )
    
	while true; do
		read -p "Do you want to use an internal password list? (yes/no): " use_internal_list
		if [ "$use_internal_list" == "yes" ]; then
			password_list=("${internal_passwords[@]}")
			break
		elif [ "$use_internal_list" == "no" ]; then
			while true; do
				read -p "Enter the path to the password list: " password_list_file
	
				if [ -f "$password_list_file" ] && [[ "$password_list_file" == *.lst || "$password_list_file" == *.txt ]]; then
					#Read the password list file into the password_list array
					mapfile -t password_list < "$password_list_file"
					break
				else
					echo "Invalid password list. File must exist and have a .lst or .txt extension."
				fi
			done
			break
		else
			echo "Invalid response. Please answer 'yes' or 'no'."
		fi
	done

##2.2 Login services to check include: SSH, RDP, FTP, and TELNET.
    #Extract ports for SSH, RDP, FTP, and Telnet from Nmap results
	ssh_port=$(echo "$nmap_results" | grep 'ssh' | grep -oP '\d+/open' | cut -d '/' -f 1)
	rdp_port=$(echo "$nmap_results" | grep 'ms-wbt-server' | grep -oP '\d+/open' | cut -d '/' -f 1)
	ftp_port=$(echo "$nmap_results" | grep 'ftp' | grep -oP '\d+/open' | cut -d '/' -f 1)
	telnet_port=$(echo "$nmap_results" | grep 'telnet' | grep -oP '\d+/open' | cut -d '/' -f 1)

	#Run Hydra using the provided or built-in username and password lists for SSH, RDP, FTP, and Telnet
	if [ -n "$ssh_port" ]; then
		sudo hydra -L "$username_list" -P "$password_list" -s "$ssh_port" ssh://"$ipaddr"
	else
		echo 'SSH service not found or no open port available.'
	fi
	
	if [ -n "$rdp_port" ]; then
		sudo hydra -L "$username_list" -P "$password_list" -s "$rdp_port" rdp://"$ipaddr"
	else
		echo 'rdp service not found or no open port available.'
	fi
	
	if [ -n "$ftp_port" ]; then
		sudo hydra -L "$username_list" -P "$password_list" -s "$ftp_port" ftp://"$ipaddr"
	else
		echo 'ftp service not found or no open port available.'
	fi
	
	if [ -n "$telnet_port" ]; then
		sudo hydra -L "$username_list" -P "$password_list" -s "$telnet_port" telnet://"$ipaddr"
	else
		echo 'telnet service not found or no open port available.'
	fi
}

##1.3 Allow the user to choose 'Basic' or 'Full'.
###1.3.1 Basic: scans the network for TCP and UDP, including the service version and weak passwords.
function basicscan()
{
	echo -e 'Running Basic scan... Please wait as this will take a while.\n'
	nmap_results=$(sudo nmap -p- -sV "$ipaddr")
	echo -e "$nmap_results"
	masscan_results=$(sudo masscan -pU:0-65535 --rate 1000 $ipaddr)
	echo -e "$masscan_results"
	hydrascan_results=$(hydrascan)
	echo -e 'Basic scan complete.'
	
	#Creating a log file
	basicscan_log="basicscan_log.txt"
	touch "$basicscan_log"
	
	#Redirect scan output to log file
	save_to_log "$basicscan_log" "$nmap_results"
	save_to_log "$basicscan_log" "$masscan_results"
	save_to_log "$basicscan_log" "$hydrascan_results"
	
	#Display completion message
	echo -e '\nBasic scan complete. Results saved to basicscan_log.txt.'
}
###1.3.2 Full: include Nmap Scripting Engine (NSE), weak passwords, and vulnerability analysis.
function fullscan()
{
	echo -e 'Running Full scan... Please wait as this will take a while.\n'
	nmap_results=$(sudo nmap -p- -sV "$ipaddr")
	echo -e "$nmap_results"
	masscan_results=$(sudo masscan -pU:0-65535 --rate 1000 $ipaddr)
	echo -e "$masscan_results"
	hydrascan_results=$(hydrascan)
	echo -e "$hydrascan_results"

#3.Mapping Vulnerabilities
##3.1Mapping vulnerabilities should only take place if Full was chosen.
##3.2Display potential vulnerabilities via NSE and Searchsploit.
	nmap_results=$(sudo nmap -sV --script vulners --script-args mincvss=5.0 $ipaddr)
	echo -e '\nFull scan complete.'
	
	#Creating a log file
	fullscan_log="fullscan_log.txt"
    touch "$fullscan_log"

	#Redirect scan output to log file
	save_to_log "$fullscan_log" "$nmap_results"
	save_to_log "$fullscan_log" "$masscan_results"
	save_to_log "$fullscan_log" "$hydrascan_results"
	save_to_log "$fullscan_log" "$nmap_results"
	
	#Display completion message
	echo -e '\nFull scan complete. Results saved to fullscan_log.txt.'
}

#Formatting
echo -e "\033[1;33mStage 2: Performing Scans\033[0m"
display_separator

echo -e '\nPerforming Enumeration and vulnerability assessment'
echo 'Basic scan includes: TCP/UDP port scan and weak password bruteforce'
echo 'Full scan includes: TCP/UDP port scan with NSE, weak password bruteforce and vulnerability analysis\n'

	#Allows user to choose between Basic and Full scans.
while true; do	
	read -p 'Do you want to perform a (Basic/Full) scan? ' dir_input

	if [ "$dir_input" = "Basic" ]; then
		basicscan
		break
		
	elif [ "$dir_input" = "Full" ]; then
		fullscan
		break
		
	else
		echo -e 'Invalid input. Please try again.\n'
		continue
	fi
done

#4.Log Results
##4.2 At the end, show the user the found information.

#Formatting
echo -e "\033[1;33mStage 3: Display results\033[0m"
display_separator

function display_logs() {
	local log_file="$1"
	echo "Displaying contents of $log_file:"
	cat "$log_file"
}

# Assuming basicscan_log and fullscan_log are the log files to display
display_logs "$chosen_dir/basicscan_log.txt"
display_logs "$chosen_dir/fullscan_log.txt"

##4.3 Allow the user to search inside the results.

function search_results() {
	local log_file="$1"
	echo -e "\nSearch inside $log_file:"
	read -p "Enter search keyword: " search_keyword
	
	if grep -qi "$search_keyword" "$log_file"; then
		grep -i "$search_keyword" "$log_file"
	else
		echo "No results found for '$search_keyword'."
	fi
}
	#Asks user if they want to search inside the results
while true; do
	read -p 'Do you want to search inside the results? (yes/no): ' search_option
	
	if [ "$search_option" = "yes" ]; then
		search_results "$basicscan_log"
		search_results "$fullscan_log"
		break
			
	elif [ "$search_option" = "no" ]; then
		break
	
	else
		echo -e 'Invalid option. Please try again.\n'
	fi		
done

##4.4 Allow to save all results into a Zip file.
function zip_logs() {
	zip -r "$chosen_dir/scan_results.zip" basicscan_log.txt fullscan_log.txt
	echo -e "\nLog files zipped as scan_results.zip in $chosen_dir."
}

	#Asks user if they want to zip the log files
while true; do	
	read -p 'Do you want to zip all the saved log files? (yes/no): ' zip_files

	if [ "$zip_files" = "yes" ]; then
		zip_logs
		echo -e 'Files successfully zipped.\n'
		break
		
	elif [ "$zip_files" = "no" ]; then
		echo -e 'Files not zipped.\n'
		break
		
	else
		echo -e 'Invalid input. Please try again.\n'
		continue
	fi
done
