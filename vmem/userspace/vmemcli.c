#include "vmemcmd.h" 

int main (int argc, char *argv[]) {
	int i = 0, ret = 0;
	char *cmd = NULL;

	if(argc < 2) {
		printf("command missing\n");
		return 0; 
	}
	cmd = argv[1];
	for(i = 0; cmds[i].name != NULL; i++) {
		if(!strcmp(cmds[i].name, cmd))
		  break;
	}

	if(cmds[i].fn) {
		ret = cmds[i].fn(argc-1, argv+1);
	}
	else {
		printf("command error, please input correct command:%d\n", i);
	}
	if(ERR_SUCCESS != ret) {
		printf("command format or execute error\n");
	}
	return 0;
}
