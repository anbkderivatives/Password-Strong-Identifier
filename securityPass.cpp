///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////																							///////////////////
/////////						�������� ������������� ��� �������������� ����������							///////////
///////																												///////
///////	 �������������� ��� ��������� ������� ������������ ,�� ������ �� ������� �� ������		    				///////
/////// username ��� password  ��� �� �������� ��� ���� salt, � ����� �������� ��� ��� �������, � �������� ������������////
/////// �� ��������� ��������� �������� �� ����� �� ������������ ��� �� password ��� ������� ����� �������.			 //////
/////// ������, ��� ���������� ��� ������������ ����� �������� (� ����������) ��� �� �������� ��� ������� username ���///// 
/////// password, ����� ������ ��� server ��� �� ������������� �����. ������� �� �� ������ ��� ������� � ��������   ///////
/////// ������������ � server ���������� ��� ������ ��� �� ����������� ��� ����� ������� � ���.						///////
///////  � �������� ������������ ���� ����� ����������� : (�)Dictionary , (�)Suspect, (�)Brute_Force �� ������		///////
/////// ����� ���������� ��������� ��� ����������� ��� ��� ������ ��� ������������.									///////
///////  ��� ��� ������������ ���������������� ��������� ����� � ����� ��� ���������� ���������� (hash functino) SHA1./////
/////// ����������, �� ��� �� ��������� ���� ��������� hash1 ������������ � ���� ������� ��� ��������� ��� password ///////
/////// ��� ��� salt, ���� ��������� ��� ������� �� ��� ��� �������� ��� ������������.								///////
/////// � hash1 ����������� �� ��� hash2, ���� hash2 ����� � ���� ������� ��� ������� ��� ����������� ��� ���		///////
/////// ����� ����������� ��� ������������ ���������� �� ��� �������� ���� salt. ��� �� ��� ����� ����� ����� ����� ///////
/////// � �������� ������������ ���� ����������� ��� ��������� ��������, ��������� ���.							///////////
#include <iostream>
#include <string>
#include <conio.h>
#include <fstream>
#include <time.h>
#include "SHA1.h"
#include "CSHA1.h"
using namespace std;

string HashString(char *);
bool Dictionary(string ,string );
bool Suspect(string ,string ,string );
bool Brute_Force(string ,string );
void correspondence_digit(char *,int &,int &,int &,int &,int &,bool &);
void control_gap(char *,char *);
  char c[36] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
      'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
int main()
{
    cout<<"\t======ANALYTHS SYNTHIMATIKWN======\n";
    string username,password,salt;
	
	cout << "Pliktrologiste username xristi:  \t";cin>>username;

	//�������� ���������� ���������
    char key;
	cout << "Pliktrologiste password xristi:  \t";
    password.erase(0, password.size());	//������������,���. �������� ��� ������������ ��� password �� ��������� 
										//��� ���� ����� � ������� ����� �������� ��� ������� ��� ��� password
										//�� �����������.
	key = '\x08';	//������ �� ��������� Backspace
    while (key != '\x0d')	//����� �� ����� enter									
    {							
    key = getch();
     if (key == '\x08')			//\x08 (������������)-->����������� ���� ��������� Backspace.��� � key ����� Backspace.
     {
      if (password.size() > 0)	//����������� ��� ������� ������ �� ����� ������ 
      {
        cout << "\x08 \x08";	//������ ��� �� ��������� �� ���������
        password.erase(password.size() - 1, 1);		//���� �������� �� ��������� �������� ��� password
      }
      continue;
     }
     else if(key != '\x0d')
     {
      password += key;
      cout << "*";
     }
    }
    cout<<"\nDwste salt:\t";
    cin>>salt;

	string sum_p_s;//sum_password_salt
    sum_p_s=(password+salt);	//�������� ��� password ��� salt ��� sum_p_s

	//�������� ������� � ����� ��� ������  *temp ��� ��� ��������� ��� sum_p_s(����� string) �� char,
	//��� ��� ���� ��� � HASH ������� ����������� ����� char
    char *temp;
    temp=&sum_p_s[0];
	string hash1=HashString(temp); //hash1=���������� hash ��� password ��� salt
	
	string method;
    string again="1";
	while(again=="1")
	{
	cout<<"\nEpilekste methodo gia analysi Synthimatikou\n";
	cout<<"1-->gia Dictionary\t2-->gia Suspect \t3-->gia Brute_Force\n";
    cin>>method; 

srand(time(NULL));
clock_t start, end;
double elapsed;
start = clock();     //=========enarksi xronou=============    

	if(method=="1")
		if (Dictionary(hash1,salt)==1) cout <<"\nTo Synthimatiko vrethike me eptyxia!\n"<<endl;
		else cout<<"\nTo Synthimatiko den vrethike.\n";
	else if(method=="2")
		if(Suspect(hash1,salt,username)==1) cout <<"\nTo Synthimatiko vrethike me eptyxia!\n"<<endl;
		else cout<<"\nTo Synthimatiko den vrethike.\n";
    else if(method=="3")
		if(Brute_Force(hash1,salt)==1) cout<<"\nTo Synthimatiko vrethike me eptyxia!\n";
		else {cout<<"\nTo Synthimatiko den vrethike.\n";
			  cout << "To diastima twn psifiwn teleiwse xwris na vrei to Synthimatiko.\n";}
	else cout<<"\nI epilogi pou dwsate den yparxei.\nDokimaste ksana\n";

end = clock();        //===========liksi xronou==============
elapsed = ((double) (end - start)) /(double) CLOCKS_PER_SEC;
cout<<"Time "<<elapsed<<endl;

	cout<<"\nThelete na dokimasete alli methodo?\n";
	cout<<"1-->gia nai || otidipote-->gia oxi\n";
	cin>>again;
	if(again!="1") again="0";
	}
system("pause");
return 0;
}

//Dictionary:
// � ���������� ��� ����� �� ������� ��� ���� ��� ������ ��� �� ������, ��� ����� ��� ��������� 
//�� ��� �������� ���� salt, ���������� ���� ���� ��� hash2 ���� �� �� ��������� �� ���  hash1
//���� ��������:
//char *temp;
//temp=&sum[0];
//hash2=HashString(temp);
//����� � ��������� ��� sum(����� string) �� char ,��� ��� ���� ��� � HASH ������� ����������� ����� char
bool Dictionary(string hash1,string salt)
{
  cout<<"\n==================================================\n";
  cout<<"\t\Dictionary Method\t\t\n";
	string line,sum;
	string hash2;
	ifstream file;
	file.open("wordlist.txt");
	if(!file.is_open()) {cout<<"\nTo anoigma tou arxeiou wordlist.txt den itan epituxes (i den yparxei)!\n";system("pause");return 0;}

  cout<<"\n=================================\n";
  cout<<"Parakalw Perimenete...";
	while (!file.eof())
	{
		file >> line ;
		//cout<<line<<endl;
		sum=line+salt;
		char *temp;
		temp=&sum[0];
		hash2=HashString(temp);
		if (hash2==hash1) return 1;
	}
	file.close();
	return 0;
}

//Suspect:
//�� �������� �� username ��� ������ � ���������� ��� Suspect ����� �� ��������� �������� ��� ������� ������������ �� 
//�� ������������ �����. �� ������������ ���������� �� ��������� �� �� �������� 
//salt ���������� ��� ���� ���� hash2 ���� �� �� ��������� �� �� hash1
//���� ��������:
//sum_p_s=onoma+salt;
//temp=&sum_p_s[0];
//hash2=HashString(temp);
//����� � ��������� ��� sum_p_s(����� string) �� char ,��� ��� ���� ��� � HASH ������� ����������� ����� char
bool Suspect(string hash1,string salt,string username)
{
  cout<<"\n==================================================\n";
  cout<<"\t Suspect Method\t\t\n";
	string onoma=username;
	string sum_p_s;
	string hash2;
    char *temp;
    string symbols=" ~!@#$%^&*()_-+={}/<>?,.;:'";//27 ��������
    string ar="0123456789";//arithmoi

  cout<<"\n=================================\n";
  cout<<"Parakalw Perimenete...";

	//�� �� password ����� �� username
	sum_p_s=onoma+salt;
	temp=&sum_p_s[0];
	hash2=HashString(temp);
	if (hash2==hash1) return 1; 

    string SUM;
    int i,s1,s2;
    int xil,ypol_xil,ek,ypol_ek,dek,ypol_dek,mon;
     
    for(s1=0;s1<26;s1++)
    for(s2=0;s2<26;s2++)
    for( i=1980;i<=2010;i++)
    {
     xil=i/1000;		//��������
     ypol_xil=i%1000;	
     ek=ypol_xil/100;	//�����������
     ypol_ek=ypol_xil%100;
     dek=ypol_ek/10;	//�������
     mon=ypol_ek%10;	//�������

	 SUM=onoma+ar[dek]+ar[mon];	//�.�.: onoma79,onoma90
	 //cout<<SUM<<endl;
	 sum_p_s=SUM+salt;
	 temp=&sum_p_s[0];
	 hash2=HashString(temp);
	 if (hash2==hash1) return 1;
        
     SUM=onoma+symbols[s2]+ar[dek]+ar[mon];//�.�.: onoma 79,onoma^90
     //cout<<SUM<<endl;
	 sum_p_s=SUM+salt;
	 temp=&sum_p_s[0];
	 hash2=HashString(temp);
	 if (hash2==hash1) return 1;

     SUM=onoma+symbols[s2]+ar[xil]+ar[ek]+ar[dek]+ar[mon];//�.�.: onoma_1979,onoma-1990
     //cout<<SUM<<endl;
	 sum_p_s=SUM+salt;
	 temp=&sum_p_s[0];
	 hash2=HashString(temp);
	 if (hash2==hash1) return 1;

     SUM=symbols[s1]+onoma+symbols[s2]+ar[xil]+ar[ek]+ar[dek]+ar[mon];//�.�.: *onoma*1979,@onoma@1990
     //cout<<SUM<<endl;
	 sum_p_s=SUM+salt;
	 temp=&sum_p_s[0];
	 hash2=HashString(temp);
	 if (hash2==hash1) return 1;
    }
    
    //reverse name
    char *temp2;
    char tem[200];
     temp2=&onoma[0];
	 int t;
     for( t=0;t<strlen(temp2);t++)
     tem[t]=*(temp2+t);
     tem[t]='\0';
     strrev(tem);
     onoma=tem;
     
    for(s1=0;s1<26;s1++)
    for(s2=0;s2<26;s2++)
    for( i=1980;i<=2010;i++)
    {
     xil=i/1000;
     ypol_xil=i%1000;
     ek=ypol_xil/100;
     ypol_ek=ypol_xil%100;
     dek=ypol_ek/10;
     mon=ypol_ek%10;
     
     
     SUM=onoma+symbols[s2]+ar[dek]+ar[mon];
     //cout<<SUM<<endl;
	 sum_p_s=SUM+salt;
	 temp=&sum_p_s[0];
	 hash2=HashString(temp);
	 if (hash2==hash1) return 1;

     SUM=onoma+symbols[s2]+ar[xil]+ar[ek]+ar[dek]+ar[mon];
     //cout<<SUM<<endl;
	 sum_p_s=SUM+salt;
	 temp=&sum_p_s[0];
	 hash2=HashString(temp);
	 if (hash2==hash1) return 1;

     SUM=symbols[s1]+onoma+symbols[s2]+ar[xil]+ar[ek]+ar[dek]+ar[mon];
     //cout<<SUM<<endl;
	 sum_p_s=SUM+salt;
	 temp=&sum_p_s[0];
	 hash2=HashString(temp);
	 if (hash2==hash1) return 1;
    }
	return 0;
}

//Brute_Force:
//� ������ ��� ��������� � Brute_Force ����� �� ���������������� ������� �������� 
//������� �� ���� ���������� ��� ������������.
//�.�: � AVBKJ ������������ i-->A,j-->V,k-->B,l-->K,m-->J
//�.�: � ER7 ������������ i-->E,j-->R,k-->7 �.�.�.
//� ��������� ������� �� ����: 
//1. ����� �� ��������� �� ���������� ����� 0..9,A..Z
//2. ���� �� ������� �� ���������� ����� 00..99,A0..AZ,B0..ZZ
//3.  >>  �� �������� �� ���������� ����� 000..999,9A0..ZZZ
//4.  >>  �� ���������� �� ���������� ����� 0000..9999,99A0..99AZ..ZZZZ
//5. ����� �� ���������� �� ���������� ����� 00000..99999,999A0..999AZ,999B0..ZZZZZ
//���� ������ �� ���������� ����� �� �������� �� salt , ��������� ���� ���� �� hash2
//�� ����� ����������� �� �� hash1.
//���� ��������:
//sum_p_s=temp1+salt;
//temp2=&sum_p_s[0];
//hash2=HashString(temp2);
//������� � ��������� ��� sum_p_s(����� string) �� char ,��� ��� ���� ��� � HASH ������� ����������� ����� char
bool Brute_Force(string hash1,string salt)
{
  int i, j, k, l, m;
  int ii = 0, jj = 0, kk = 0, ll = 0, mm = 0;
  char start[6]=""; 
  char end[6]  =""; 
  bool antistoixia = false;
  string hash2;
  string temp1;
  string sum_p_s;
  char *temp2;
  
  cout<<"\n==================================================\n";
  cout<<"\t\tBrute_Force Method\t\t\n";
  
  int apodoxi;
  cout<<"\nThelete na dwsete Diastima anazitisis?\n";
  cout<<"1-->gia nai || otidipote-->gia oxi\n (Simeiwsi: Ean den dwsete diastima, i anazitisi tha parei olous tous \ndynatous syndiasmous 5psifiwn me apotelesma, na exei megali kathysterisi)\n";
  cin>>apodoxi;
  if(apodoxi==1)
  {
	control_gap(start,end);
  }

  cout<<"\n=================================\n";
  cout<<"Parakalw Perimenete...";

  int len = strlen(start);
  int f = 0;	//flag
  if (len == 1 || len == 0)
  {
    f = 1;
    //cout << "eimai sta 1a psifia\n";system("pause");
    correspondence_digit(start,ii,jj,kk,ll,mm,antistoixia);

    for (i = ii; i < 36; i++)
    {
      start[0] = c[i];
      start[1] = '\0';
      
      //cout << start << endl;
      
      temp1=start;
      sum_p_s=temp1+salt;
      temp2=&sum_p_s[0];
      hash2=HashString(temp2);
      if (hash2==hash1) return 1;
      if (strcmp(start, end) == 0) return 0;
    }
  }
  if (len == 2 || f == 1)
  {
    f = 1;
    //cout << "eimai sta 2a psifia\n";system("pause");
    if (antistoixia == true){ii = 0;jj = 0;}
    else correspondence_digit(start,ii,jj,kk,ll,mm,antistoixia);

    for (i = ii; i < 36; i++)
	{
    for (j = jj; j < 36; j++)
    {
      start[0] = c[i];
      start[1] = c[j];
      start[2] = '\0';
      
      //cout << start << endl; 
      
      temp1=start;
      sum_p_s=temp1+salt;
      temp2=&sum_p_s[0];
      hash2=HashString(temp2);
      if (hash2==hash1) return 1;
      if (strcmp(start, end) == 0) return 0;
    }
	jj=0;
	}
  }
  if (len == 3 || f == 1)
  {
    f = 1;
    //cout << "eimai sta 3a psifia\n";system("pause");
    if (antistoixia == true){ii = 0;jj = 0;kk = 0;}
    else correspondence_digit(start,ii,jj,kk,ll,mm,antistoixia);
    
    for (i = ii; i < 36; i++)
	{
      for (j = jj; j < 36; j++)
    {
    for (k = kk; k < 36; k++)
    {
      start[0] = c[i];
      start[1] = c[j];
      start[2] = c[k];
      start[3] = '\0';
      
      //cout << start << endl; 
      
      temp1=start;
      sum_p_s=temp1+salt;
      temp2=&sum_p_s[0];
      hash2=HashString(temp2);
      if (hash2==hash1) return 1;
      if (strcmp(start, end) == 0) return 0;
    }
	kk=0;
    }
	jj=0;
    }
  }
  if (len == 4 || f == 1)
  {
    f = 1;
    //cout << "eimai sta 4a psifia\n";system("pause");
    if (antistoixia == true){ii = 0;jj = 0;kk = 0;ll = 0;}
    else correspondence_digit(start,ii,jj,kk,ll,mm,antistoixia);
    
    for (i = ii; i < 36; i++)
	{
      for (j = jj; j < 36; j++)
	{
        for (k = kk; k < 36; k++)
	{
    for (l = ll; l < 36; l++)
    {
      start[0] = c[i];
      start[1] = c[j];
      start[2] = c[k];
      start[3] = c[l];
      start[4] = '\0';
      
      //cout << start << endl; 
      
      temp1=start;
      sum_p_s=temp1+salt;
      temp2=&sum_p_s[0];
      hash2=HashString(temp2);
      if (hash2==hash1) return 1;
      if (strcmp(start, end) == 0) return 0;
    }
	ll=0;
	}
	kk=0;
	}
	jj=0;
	}
  }
  if (len == 5 || f == 1)
  {
    //cout << "eimai sta 5a psifia\n";system("pause");
    if (antistoixia == true){ii = 0;jj = 0;kk = 0;ll = 0;mm = 0;}
    else correspondence_digit(start,ii,jj,kk,ll,mm,antistoixia);
    
    for (i = ii; i < 36; i++)
	{
      for (j = jj; j < 36; j++)
	{
        for (k = kk; k < 36; k++)
	{
          for (l = ll; l < 36; l++)
	{
    for (m = mm; m < 36; m++)
    {
      start[0] = c[i];
      start[1] = c[j];
      start[2] = c[k];
      start[3] = c[l];
      start[4] = c[m];
      start[5] = '\0';
      
      //cout << start << endl; 
      
      temp1=start;
      sum_p_s=temp1+salt;
      temp2=&sum_p_s[0];
      hash2=HashString(temp2);
      if (hash2==hash1) return 1;
      if (strcmp(start, end) == 0) return 0;
    }
	mm=0;
    }
	ll=0;
	}
	kk=0;
	}
	jj=0;
	}
  }
    
}//Broute_Force

//��������� ������������ ������
//��������������� ��� ��� ������������ ��� start, ���� ����� � ���� ��� ����������� 
//���������� ���� Brute_Force. ������, ���������������� ��� ����� ��� start �� ��������
//ii,jj,kk,ll,mm ������� �� �� ����� ���. �.�: �� �� ����� ��� start ����� 3 ���� 
//�� ���������������� ��� ����� ���� ���� �� �������� ii,jj,kk.
void correspondence_digit(char *start,int &ii,int &jj,int &kk,int &ll,int &mm,bool &antistoixia)
{
     int st_c;//start counter
     int cc;//c counter
     int g;
     int *temp;
    //���������� ������������ ������ �� ���� ���������� i,j,k,l,m
    temp=new int[strlen(start)];
    for ( st_c = 0; st_c < strlen(start); st_c++)
      for ( cc = 0; cc < 36; cc++)
        if (start[st_c] == c[cc])
          temp[st_c] = cc;

    for ( g = 0; g < strlen(start); g++)
      if (g == 0) ii = temp[g];
      else if (g == 1) jj = temp[g];
      else if (g == 2) kk = temp[g];
      else if (g == 3) ll = temp[g];
      else mm = temp[g];//(g==4)
      
    antistoixia = true;
}

//control_gap:
//��������������� ��� ��� ������ ��� ������ ����������� ���������� ����������� 
//���� Brute_Force ,�� ����� �� ���������� ����� �� ������������ ���������,
//���� ��� � ���������� ��������� ��� ���������� �� ����� (�����: ��������) ��� ����� �����.
void control_gap(char *start,char *end)
{
  int egkuro;
  bool continuant=true;
    while(continuant==true)
    {
    egkuro=0;
    while(egkuro==0){
    cout<<"Dwste start (Arxi Diastimatos) [prepei na einai to poly 5psifio]\n";
    cin>> start;
    if(strlen(start)<=5) egkuro=1;
    }
    egkuro=0;
    while(egkuro==0){
    cout<<"Dwste end (Telos Diastimatos) [prepei na einai to poly 5psifio]\n";
    cin>> end;
    if(strlen(end)<=5) egkuro=1;
    }

    if(strlen(start)==strlen(end))
      if(strcmp(start,end)>0)cout<<"\nLathos dedomena!\nPrepei na isxuei start <= end symfwna me tin alfabitiki taksinomisi.\n\n";
      else continuant=false;
    else if(strlen(start)<strlen(end))
      if(strcmp(start,end)>0)
      {
        if(strcmp(end,start)>0)
        cout<<"\nLathos dedomena!\nPrepei na isxuei start <= end symfwna me tin alfabitiki taksinomisi.\n\n";
        else continuant=false;
      }
      else continuant=false;
    else cout<<"\nLathos dedomena!\nPrepei na isxuei start < end se psifia.\n\n";
    }
}

//HASH SHA1
string HashString(char *temp)
{
	char *tszString;
	tszString=temp;
	
	CSHA1 sha1;
	sha1.Update((UINT_8*)tszString, _tcslen(tszString) * sizeof(TCHAR));
	sha1.Final();
	std::basic_string<TCHAR> strReport;
	sha1.ReportHashStl(strReport, CSHA1::REPORT_HEX_SHORT);

	return strReport.c_str();
}
