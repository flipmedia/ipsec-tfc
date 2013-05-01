/*
 * Helper tool to generate probability function table
 * May be used for Random-Early-Dropping in TFC queuing.
 *
 * Usage: Generate desired function y=f(x), where y determines the probability
 * of dropping a packet(0...100%) and x the usage of the packet queue (0..100%).
 *
 * Typically, a low usage should not drop packets but a higher usage
 * exponentially more so.
 */

#include <stdio.h>
#include <unistd.h>
#include <math.h>


int main(int argc, char **argv) {
	
	double y;
	int debug;
	
	if (argc < 2)
		debug=0;
	else
		debug=1;
	
	
	if (!debug)
		printf("{ ");
			
	for (int x = 0; x <= 100; x++) {
		//double tmp = (double)x/21;
		//y = exp((double)x/21)-2;
		y = exp((double)(x-40)/13)-1;
		
		if (y < 0) y = 0;
		if (y > 100) y = 100;
		
		if (debug)
			printf("P(%d)=%04.1f\n",x,y);
		else
			printf("%.0lf, ", floor(y));
	}
	
	if (!debug)
		printf("};\n");
	
	return 0;
}
