#include "populate.h"


Rule *rules_ds = NULL;
int count = 0;

void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
	ETHER_Frame custom_frame;
	populate_packet_ds(header,packet,&custom_frame);
	rule_matcher(rules_ds,&custom_frame,count);
}

int main(int argc, char *argv[]) 
{
		FILE *file = fopen(argv[2],"r");
		if (file == NULL)
			exit(EXIT_FAILURE); // == exit(1)

		count = count_lines_from_file(file);

		rules_ds = malloc(count * sizeof(*rules_ds));

		read_rules(file, rules_ds, count);

		if(check_struct(rules_ds,count))
		{
			generate_syslog("An error has occured check ids.rules !!","--IDS CRIT--");
			exit(EXIT_FAILURE);
		}
		fclose(file);

        char *device = argv[1];
        char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_t *handle;

        handle = pcap_create(device,error_buffer);
        pcap_set_timeout(handle,10);
        pcap_activate(handle);
        int total_packet_count = 20;

		generate_syslog("Succesful Program Launch",LOG_PROG);

        pcap_loop(handle, total_packet_count, my_packet_handler, NULL);
		free_memory(rules_ds, count);

		generate_syslog("Succesful Program Close",LOG_PROG);
		
		closelog();
        return 0;
}
