#include "common.h"
#include "ticket.h"

// actually ticket.db has a fixed size
#define BUFFER_SIZE	TICKDB_AREA_SIZE
#define TICK_SEARCH 0x00, 0x04, 0x00, 0x30, 0x00, 0x00, 0x8A, 0x02
// #define SILENT

u32 ValidateTicket(Ticket* ticket) {
    const u8 magic[] = { SIG_TYPE };
    if ((memcmp(ticket->sig_type, magic, sizeof(magic)) != 0) ||
        ((strncmp((char*) ticket->issuer, TICKET_ISSUER, 0x40) != 0) &&
        (strncmp((char*) ticket->issuer, TICKET_ISSUER_DEV, 0x40) != 0)))
        return 1;
    return 0;
}

u32 FindTicket(Ticket* ticket, u8* data, u8* title_id, bool force_legit) {
    u32 count = 0;
    u32 found = (u32) -1;
    for (u32 i = 0; i < (TICKDB_AREA_SIZE / 0x200); i++) {
        Ticket* tick = (Ticket*) (data + (i*0x200) + 0x18);
        if ((getle32(data + 0x10) == 0) || (getle32(data + 0x14) != sizeof(Ticket))) continue;
        if (ValidateTicket(tick) != 0) continue;
        #ifdef SILENT
        if (memcmp(title_id, tick->title_id, 8) != 0) continue; // title id not matching
        #endif
        fprintf(stderr, "%04u %08X%08X @ %08X\n", count++, getbe32(tick->title_id), getbe32(tick->title_id + 4), (i*0x200));
        if (memcmp(title_id, tick->title_id, 8) != 0) continue; // title id not matching
        if (force_legit && (getbe64(tick->ticket_id) == 0)) continue; // legit check
        fprintf(stderr, "-> legit (%08X%08X), found!\n", getbe32(tick->ticket_id), getbe32(tick->ticket_id + 4));
        memcpy(ticket, tick, sizeof(Ticket));
        found = (i*0x200);
    }
    
    return found;
}

u32 LoadActivePartition(u8* buffer, const char* path) {
    const u32 area_offsets[] = { TICKDB_AREA_OFFSETS };
    FILE* fp = fopen(path, "rb");
    
    // find active partition / offset
    if (fread(buffer, 1, 0x200, fp) != 0x200) {
        fclose(fp);
        return 1;
    }
    
    // active partition
    u32 p = (getle32(buffer + 0x130)) ? 1 : 0;
    fprintf(stderr, "active partition: %u\npartition offset: %08X\npartition end   : %08X\n",
        p, area_offsets[p], area_offsets[p] + TICKDB_AREA_SIZE);
        
    // load partition
    fseek(fp, area_offsets[p], SEEK_SET);
    if (fread(buffer, 1, TICKDB_AREA_SIZE, fp) != TICKDB_AREA_SIZE) {
        fclose(fp);
        return 1;
    }
    
    fclose(fp);
    return 0;
}

void showhelp_exit() {
	fprintf(stderr, " usage: ticksmart [ticket.db]\n\n");
	exit(0);
}

int main( int argc, char** argv )
{
    u8* buffer = (u8*) malloc(TICKDB_AREA_SIZE);
    u8 title_id[8] = { TICK_SEARCH };
    Ticket ticket;
    
	fprintf(stderr, "\nTicketDB-smartget by d0k3\n");
	fprintf(stderr, "-------------------------\n\n");
	
	if (argc != 2) showhelp_exit();
    if (LoadActivePartition(buffer, argv[1]) != 0) {
        fprintf(stderr, "load active partition failed!\n");
        return 1;
    }
    fprintf(stderr, "searching for ticket %08X%08X...\n", getbe32(title_id), getbe32(title_id + 4));
    u32 found = FindTicket(&ticket, buffer, title_id, true);
    if (found == (u32) -1) {
        fprintf(stderr, "search failed!\n");
        return 1;
    }
    fprintf(stderr, "\nticket FOUND: %08X\n", found);
	
	return 0;
}
