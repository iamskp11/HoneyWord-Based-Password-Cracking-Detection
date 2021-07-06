#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <ctype.h>

#define ll signed long long int
#define mod 192549818945291 
char to_ret[70];
int curr_index=11;
int faults=0;


// generate a random small letter character
char randomChar()
{
	char asc=(rand()%26)+97;
	//printf("I am returning %c\n",asc);
	return asc;
}

int randomInt()
{
	int num=(rand()%curr_index);
	if(num==0) return randomInt();
	return num;
}

bool is_honeypot(char ci[3])
{
	return strcmp(ci,"1")==0 || strcmp(ci,"2")==0 || strcmp(ci,"3")==0 || strcmp(ci,"4")==0 || strcmp(ci,"5")==0 
	    || strcmp(ci,"6")==0 || strcmp(ci,"7")==0 || strcmp(ci,"8")==0 || strcmp(ci,"9")==0 || strcmp(ci,"10")==0;
}



// Generates (k) honeywords and write into F1.txt
void HoneyGenerate(char *username,int k)
{
	int HoneyIndex[k+1];
	HoneyIndex[k]=curr_index;
	int st=0;
	for(int i=0;i<k;i++)
	{
		int possible=randomInt();
		int put=1;
		for(int j=0;j<i;j++)
		{
			if(HoneyIndex[j]==possible) put=0;
		}
		if(put) HoneyIndex[i]=possible;
		else i--;
	}
	//for(int i=0;i<=k;i++) printf("%d ", HoneyIndex[i]);

	// Write into F1 file
	FILE *f=fopen("F1.txt","a");
	fprintf(f, "%s ", username);
	for(int i=0;i<=k;i++) fprintf(f,"%d ",HoneyIndex[i]);
	fprintf(f, "\n");
	fclose(f);
}

/*
// Create a hash of string pass , with probability of collision = 10^(-15)
const char *hashIt(char *pass)
{
	ll hs=0,p=1;
	int n=strlen(pass);
	for(int i=0;i<n;i++)
	{
		hs=(hs+p*pass[i])%mod;
		p=(p*67)%mod;
	}
	//printf(" hashing int is %lld\n",hs);
	//static char to_ret[]="";
	for(int i=0;i<16;i++) to_ret[i]=' ';
	to_ret[0]='\0';
	while(hs)
	{
		ll d=hs%10;
		char ch=d+48;
		strncat(to_ret,&ch,1);
		hs/=10;
	}
	//int m=strlen(to_ret);
	//printf("Oejd %s\n",to_ret);
	return to_ret;
}
*/

const char *hashIt(char *pass)
{
	system("rm hashfile.txt");
	FILE *f=fopen("temp.txt","w");
	fprintf(f,"%s",pass);
	fclose(f);
	system("md5deep temp.txt >> hashfile.txt");
	// destroy temp.txt since it contains password
	//system("rm temp.txt");

	FILE *f1=fopen("hashfile.txt","r");
	char line[100];
	to_ret[0]='\0';
	while(fgets(line,100,f1)!=NULL)
	{
		for(int i=0;1;i++)
		{
			char ch=line[i];
			//printf("%d ", ch);
			if(ch==32) break;
			strncat(to_ret,&ch,1);
		}
	}
	//printf("Returning %s\n",to_ret);
	return to_ret;
}

/*
void Honeypots()
{
	// creates 10 users with ith index as i and password as pi 
	// index 1 to 10 are honeypot indices 

	// Assumption : All honeypot passwords are of length 9 only

	for(int i=1;i<=10;i++)
	{
		char pass[9];
		for(int j=0;j<9;j++)
		{
			pass[j]=randomChar();
		}
		//printf("Password generated is %s\n",pass);
		//printf("Got %s\n",hashIt(pass));
		char *hash_of_pass=hashIt(pass);
		//printf("hashed to %s\n",hash_of_pass);
		FILE *f=fopen("F2.txt","a+");
		fprintf(f,"%d %s\n",i,hash_of_pass);
		fclose(f);
	}
}
*/

void Honeypots()
{
	// creates 10 users with ith index as i and password as pi 
	// index 1 to 10 are honeypot indices 

	// Assumption : All honeypot passwords are of length <=12 only
	char password[12]="";
	FILE *f=fopen("PasswordFile.txt","r");
	FILE *f2=fopen("F2.txt","a+");
	int i=1;
	while(fgets(password,12,f)!=NULL)
	{

		// Just checking
		int len=strlen(password);
		if(password[len-1]=='\n') password[len-1]=0;
		// End checking


		//printf("%s\n", password);
		char *hash_of_pass=hashIt(password);
		fprintf(f2, "%d %s\n",i,hash_of_pass);
		i++;
	}
	fclose(f);
	fclose(f2);
}


// Ask for username and password
// Append username, hash in F2.txt
// Append Username and HoneyIndices in F1.txt

void register_user()
{
	char username[12],password[12];
	printf("Enter Username : ");
	scanf("%s",username);
	printf("Enter Password : ");
	scanf("%s",password);

	char *hash_of_pass=hashIt(password);
	// Append {index,hash_password} in F2 file
	
	FILE *f=fopen("F2.txt","a+");
	fprintf(f,"%d %s\n",curr_index,hash_of_pass);
	fclose(f);
	// Append {username, k+1 indices} in F1 file
	HoneyGenerate(username,5);

	// Append {username,correct_index} in HoneyChecker Server

	FILE *f1=fopen("HCServer.txt","a+");
	fprintf(f1, "%s %d\n", username,curr_index);
	fclose(f1);
}

void Login()
{
	char username[12],password[12];
	printf("Enter Username : ");
	scanf("%s",username);
	printf("Enter Password : ");
	scanf("%s",password);
    
    // Get the corresponding index from HoneyChecker Server 
	char ci[3]="";
	FILE *f3=fopen("HCServer.txt","r");
	char line3[40];
	while(fgets(line3,40,f3)!=NULL)
	{
		char uname[12]="";
		int i;
		for(i=0;1;i++)
		{
			char ch=line3[i];
			if(ch==32) break;
			strncat(uname,&ch,1);
		}
		if(strcmp(uname,username)) continue;
		i++;
		for(;1;i++)
		{
			char ch=line3[i];
			if(ch==10) break;
			strncat(ci,&ch,1);
		}
		break;
	}
	fclose(f3);

    //Flag
    int flag=0;

	// Get the hash of password
    char *hash_of_pass=hashIt(password);

    // Check for username entry in F1 file
    FILE *f1=fopen("F1.txt","r");
    char line[40];

    while(fgets(line,40,f1)!=NULL)
    {
    	//printf("1 username : %s password : %s\n",username,password);
    	//printf("Got line : (%s)\n",line);
    	char uname[12]="";
    	//uname[0]='\0';
    	int i;
    	for(i=0;1;i++)
    	{
    		char ch=line[i];
    		//printf("%d-->%c ",i,ch);
    		if(ch==32) break;
    		//printf("2 username : %s password : %s ",username,password);
    		strncat(uname,&ch,1);
    		//printf("3 username : %s password : %s\n",username,password);
    	}
    	//printf("uname is (%s) username is (%s)\n",uname,username);
    	if(strcmp(username,uname)==0)
    	{
    		//printf("Found\n");
    		// for this username , find if some index matches with corresponding password in F2 file
    		while(1)
    		{
	    		char idx[3]="";
	    		i++;
	    		for(;1;i++)
	    		{
	    			char ch=line[i];
	    			if(ch==32 || ch==10) break;
	    			strncat(idx,&ch,1);
	    		}
	    		if(strcmp(idx,"")==0) break;
	    		//printf("Found index (%s)\n",idx);
	    		FILE *f2=fopen("F2.txt","r");
	    		char line2[40];
	    		while(fgets(line2,40,f2)!=NULL)
	    		{
	    				char indx[3]="";
	    				int i;
	    				//printf("1 idx is (%s) ",idx);
	    				//char *idx2=idx;
	    				for(i=0;1;i++)
	    				{
	    					char ch=line2[i];
	    					if(ch==32) break;
	    					strncat(indx,&ch,1);
	    				}
	    				//printf("2 Index is (%s) idx is (%s)\n",indx,idx);
	    				if(strcmp(idx,indx)!=0) continue;
	    				//printf("Same same\n");
	    				i++;
	    				char pss[20]="";
	    				for(;1;i++)
	    				{
	    						char ch=line2[i];
	    						if(ch==32 || ch==10) break;
	    						strncat(pss,&ch,1);
	    				}
	    				//printf("pss is %s to be matched with  %s\n", pss,hash_of_pass);
	    				if(strcmp(hash_of_pass,pss)==0)
	    				{
	    					flag=1;
	    					if(is_honeypot(idx))
    						{
    							faults++;
    							printf("[!!] Attempt to login with HoneyPot account\n");
    							break;
    						}
	    					if(strcmp(idx,ci)==0)
	    					{
	    						printf("%s\n",idx);
	    						// check if idx is honeypot account
	    						/*if(is_honeypot(idx))
	    						{
	    							printf("[!!] Attempt to login with HoneyPot account\n");
	    						}
	    						else */printf("[+] Login successful. Access Granted\n");
	    					}
	    					else 
	    					{
	    						faults++;
	    						printf("[-]Attempt to login with honeyword account\n");
	    					}
	    				}

	    		}
	    		fclose(f2);
    		}
    		fclose(f1);
    		if(!flag)printf("[-]Password Incorrect\n");
    		return ;
    	} 
    }
    printf("\n[-]Username and/or Password Not Found\n");
    fclose(f1);
}


void info()
{
	printf("\n--------Enter---------\n1 for Registration\n2 for Login\n3 for Program Termination\n-------------------\n");
}

void createfiles()
{
	system("rm F2.txt");
	system("rm F1.txt");
	system("rm HCServer.txt");
	system("touch F2.txt");
	system("touch F1.txt");
	system("touch HCServer.txt");
}

int main()
{
	//check();
	createfiles();
	srand(time(NULL));
	Honeypots();

	

	while(1)
	{
		if(faults>=5)
		{
			printf("\n!!----------------!!\n[!!] Attempt to hack detected\nTerminating\n");
			break;

		}
		info();
		int ch;
		scanf("%d",&ch);
		if(ch==3) break;
		if(ch==1) 
		{
			register_user();
			curr_index++;
		}
		else if(ch==2)
		{
			if(curr_index==11)
			{
				printf("[!!] No users yet. Please Register first\n");
				continue;
			}
			Login();
		}
		else 
		{
			printf("\nInvalid Entry!\n");
		}
	}
	printf("\nProgram Terminated\n");
	return 0;
}