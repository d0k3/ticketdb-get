#include "common.h"
#include "ticket.h"

// actually ticket.db has a fixed size
#define BUFFER_SIZE	(64 * 1024 * 1024)

void showhelp_exit() {
	fprintf(stderr, " usage: tickget [ticket.db]\n\n");
	exit(0);
}

int main( int argc, char** argv )
{
	u8* tdb;
    u32 fsize;
    
	fprintf(stderr, "\nTicketDB-get by d0k3\n");
	fprintf(stderr, "---------------------\n\n");
	
	if(argc != 2) showhelp_exit();

    tdb = (unsigned char*) malloc(BUFFER_SIZE);
	if (tdb == NULL) {
		fprintf(stderr, "out of memory");
		return 0;
	}
    
	FILE* fp = fopen(argv[1], "rb");
	if(fp == NULL) {
		fprintf(stderr, "open %s failed!\n\n", argv[1]);
		return 0;
	}
    fsize = fread(tdb, 1, BUFFER_SIZE, fp);
    fclose(fp);
    
    const u8 magic[] = { SIG_TYPE };
    u32 last_i = 0;
    u32 n_tick = 0;
    // printf("no;offset;change;title_id;titlekey;ticket_id;console_id;eshop_id");
    printf("no;offset;change;size;count;title_id\n");
    for (u32 i = 0x18; i + sizeof(Ticket) <= fsize; i++) {
        Ticket* ticket = (Ticket*) (tdb + i);
        u32 size = *((u32*) (tdb + i - 0x04));
        u32 count = *((u32*) (tdb + i - 0x08));
        if ((memcmp(ticket->sig_type, magic, sizeof(magic)) != 0) ||
            ((strncmp((char*) ticket->issuer, TICKET_ISSUER, 0x40) != 0) &&
            (strncmp((char*) ticket->issuer, TICKET_ISSUER_DEV, 0x40) != 0)))
            continue; // magics not found
        /*printf("%lu;%08X;+%08X;%016llX;%016llX%016llX;%016llX;%08X;%08X",
            n_tick++, i, last_i, getbe64(ticket->title_id),
            getbe64(ticket->titlekey), getbe64(ticket->titlekey + 8),
            getbe64(ticket->ticket_id), getbe32(ticket->console_id),
            getbe32(ticket->eshop_id));*/
        /*printf("%u;%08X;+%X;%08X%08X\n",
            n_tick++, i, i - last_i, getbe32(ticket->title_id), getbe32(ticket->title_id + 4));*/
        printf("%u;%u;+%u;%u;%u;0x%08X%08X\n",
            n_tick++, i, i - last_i, size, count, getbe32(ticket->title_id), getbe32(ticket->title_id + 4));
        last_i = i;
    }
	
	free(tdb);
	
	return 1;
}
