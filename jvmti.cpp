#include <stdlib.h>
#include <string.h>

#include <jvmti.h>
#include <jni.h>
#include <jni_md.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>


#include <iostream>
#include <fstream>
using namespace std;


#define PUBLICKEY	"rsa_private_key.pem"
#define OPENSSLKEY	"rsa_public_key.pem"
#define BUFFSIZE	1024
char* my_encrypt( char *str, char *path_key );  /* 加密 */


char* my_decrypt( char *str, char *path_key );  /* 解密 */


int totalpackage;

char		linebuffer[2048];
const char	* base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int fileLength;


void PRINT_FILE( const char *cmd, ... )
{
	FILE	*f = fopen( "/opt/logs/cmf/decrypt.log", "a+" );
	time_t	timep;
	time( &timep );
	fprintf( f, "%s", asctime( gmtime( &timep ) ) );

	va_list args;                   /* 定义一个va_list类型的变量，用来储存单个参数 */
	va_start( args, cmd );          /* 使args指向可变参数的第一个参数 */
	vfprintf( f, cmd, args );       /* 必须用vprintf等带V的 */
	va_end( args );                 /* 结束可变参数的获取 */

	fclose( f );
}


time_t StringToDatetime( string str )
{
	char	*cha = (char *) str.data();
	tm	tm_;
	int	year, month, day, hour, minute, second;
	sscanf( cha, "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &minute, &second );
	tm_.tm_year	= year - 1900;
	tm_.tm_mon	= month - 1;
	tm_.tm_mday	= day;
	tm_.tm_hour	= hour;
	tm_.tm_min	= minute;
	tm_.tm_sec	= second;
	tm_.tm_isdst	= 0;
	time_t t_ = mktime( &tm_ );
	return(t_);
}


static int base64_encode( char *str, int str_len, char *encode, int encode_len )
{
	BIO	*bmem, *b64;
	BUF_MEM *bptr;
	b64	= BIO_new( BIO_f_base64() );
	bmem	= BIO_new( BIO_s_mem() );
	b64	= BIO_push( b64, bmem );
	BIO_write( b64, str, str_len ); /* encode */
	BIO_flush( b64 );
	BIO_get_mem_ptr( b64, &bptr );
	if ( bptr->length > encode_len )
	{
		PRINT_FILE( "encode_len too small\n" );
		return(-1);
	}
	encode_len = bptr->length;
	memcpy( encode, bptr->data, bptr->length );
	BIO_free_all( b64 );
	return(encode_len);
}


static int base64_decode( char *str, int str_len, char *decode, int decode_buffer_len )
{
	PRINT_FILE( "base 64 decode begin %d\n", str[0] );
	PRINT_FILE( "before base64 decode str is %s", str );

	int	len = 0;
	BIO	*b64, *bmem;
	b64	= BIO_new( BIO_f_base64() );
	bmem	= BIO_new_mem_buf( str, str_len );
	bmem	= BIO_push( b64, bmem );
	len	= BIO_read( bmem, decode, str_len );
	PRINT_FILE( "after base64 decode  len is %d\n", len );
	decode[len] = 0;
	BIO_free_all( bmem );

	PRINT_FILE( "decode result begin %d\n", decode[0] );

	return(0);
}


char *unbase64( char *input, int length )
{
	BIO	*b64, *bmem;
	int	len	= 0;
	char	*buffer = (char *) malloc( 1024 );
	/* char *buffer = (char *)malloc(length); */
	memset( buffer, 0, length );

	b64 = BIO_new( BIO_f_base64() );
	BIO_set_flags( b64, BIO_FLAGS_BASE64_NO_NL );

	bmem	= BIO_new_mem_buf( input, length );
	bmem	= BIO_push( b64, bmem );

	len = BIO_read( bmem, buffer, length );
	PRINT_FILE( "len is %d in unbase64\n", len );
	buffer[len] = 0;

	BIO_free_all( bmem );

	return(buffer);
}


int base64_decode_src( const char * base64, unsigned char * bindata )
{
	int		i, j;
	unsigned char	k;
	unsigned char	temp[4];
	for ( i = 0, j = 0; base64[i] != '\0'; i += 4 )
	{
		memset( temp, 0xFF, sizeof(temp) );
		for ( k = 0; k < 64; k++ )
		{
			if ( base64char[k] == base64[i] )
				temp[0] = k;
		}
		for ( k = 0; k < 64; k++ )
		{
			if ( base64char[k] == base64[i + 1] )
				temp[1] = k;
		}
		for ( k = 0; k < 64; k++ )
		{
			if ( base64char[k] == base64[i + 2] )
				temp[2] = k;
		}
		for ( k = 0; k < 64; k++ )
		{
			if ( base64char[k] == base64[i + 3] )
				temp[3] = k;
		}

		bindata[j++] = ( (unsigned char) ( ( (unsigned char) (temp[0] << 2) ) & 0xFC) ) |
			       ( (unsigned char) ( (unsigned char) (temp[1] >> 4) & 0x03) );
		if ( base64[i + 2] == '=' )
			break;

		bindata[j++] = ( (unsigned char) ( ( (unsigned char) (temp[1] << 4) ) & 0xF0) ) |
			       ( (unsigned char) ( (unsigned char) (temp[2] >> 2) & 0x0F) );
		if ( base64[i + 3] == '=' )
			break;

		bindata[j++] = ( (unsigned char) ( ( (unsigned char) (temp[2] << 6) ) & 0xF0) ) |
			       ( (unsigned char) (temp[3] & 0x3F) );
	}
	return(j);
}


char *my_encrypt( char *str, char *path_key )
{
	char	*p_en;
	RSA	*p_rsa;
	FILE	*file;
	int	flen, rsa_len;
	if ( (file = fopen( path_key, "r" ) ) == NULL )
	{
		perror( "open key file error" );
		return(NULL);
	}

	if ( (p_rsa = PEM_read_RSAPrivateKey( file, NULL, NULL, NULL ) ) == NULL )
	{
		ERR_print_errors_fp( stdout );
		return(NULL);
	}


	flen	= strlen( str );
	rsa_len = RSA_size( p_rsa );
	p_en	= (char *) malloc( rsa_len + 1 );
	memset( p_en, 0, rsa_len + 1 );
	int retlen = RSA_private_encrypt( rsa_len, (unsigned char *) str, (unsigned char *) p_en, p_rsa, RSA_NO_PADDING );
	if ( retlen < 0 )
	{
		return(NULL);
	}
	RSA_free( p_rsa );
	fclose( file );

	char	* encode	= new char[2048];
	int	encode_len	= 2048;
	base64_encode( p_en, retlen, encode, encode_len );


	return(encode);
}


char *my_decrypt( char *str_base64, char *path_key )
{
	char	*p_de;
	RSA	*p_rsa;
	FILE	*file;
	int	rsa_len;
	/* return  shouldnt exist */
	char	str[2048];
	int	decode_buffer_len	= 2048;
	int	len			= base64_decode( str_base64, strlen( str_base64 ), str, decode_buffer_len );


	string strPublicKey = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC783zDzmUBRsPyseslJBsK5qDG\nidLIBLk5W8P4eus9Qjfijkf+BkCONDIjx9S0jCUBVBeQmQXa0g0SipOqN/aUpyna\n62Zqk7M1RhtRQ4f4OhNzYWQJPhnTsQ81iBAYqqd0JjTAzHWmxil9lKw3B3R2lO4S\n3V88ijrNQQuIW12YIwIDAQAB\n-----END PUBLIC KEY-----";

	BIO	*bio		= NULL;
	char	*chPublicKey	= const_cast<char *>(strPublicKey.c_str() );
	if ( (bio = BIO_new_mem_buf( chPublicKey, -1 ) ) == NULL )      /* 从字符串读取RSA公钥 */
	{
		cout << "BIO_new_mem_buf failed!" << endl;
	}
	p_rsa = PEM_read_bio_RSA_PUBKEY( bio, NULL, NULL, NULL );       /* 从bio结构中得到rsa结构 */
	if ( !p_rsa )
	{
		PRINT_FILE( "read error!!!!!!!!!!!!!!!!!!!!!!\n" );
		ERR_load_crypto_strings();
		char errBuf[512];
		ERR_error_string_n( ERR_get_error(), errBuf, sizeof(errBuf) );
		cout << "load public key failed[" << errBuf << "]" << endl;
		BIO_free_all( bio );
	}


	rsa_len = RSA_size( p_rsa );
	p_de	= (char *) malloc( rsa_len + 1 );

	PRINT_FILE( "rsa_len+1 is %d in my_decrypt \n", rsa_len + 1 );

	memset( p_de, 0, rsa_len + 1 );

	int ret = RSA_public_decrypt( rsa_len, (unsigned char *) str, (unsigned char *) p_de, p_rsa, RSA_NO_PADDING );
	PRINT_FILE( "ret is %d\n", ret );
	if ( ret < 0 )
	{
		return(NULL);
	}
	PRINT_FILE( "decrypt str is %s\n", p_de );
	RSA_free( p_rsa );
	return(p_de);
}


int filelength( FILE *fp )
{
	int num;
	fseek( fp, 0, SEEK_END );
	num = ftell( fp );
	fseek( fp, 0, SEEK_SET );
	fileLength = num;
	return(num);
}


unsigned char *readfile( char *path )
{
	FILE		*fp;
	int		length;
	unsigned char	*ch;
	if ( (fp = fopen( path, "r" ) ) == NULL )
	{
		PRINT_FILE( "open file %s error.\n", path );
		exit( 0 );
	}else  {
		PRINT_FILE( "file is opened\n" );
	}
	length	= filelength( fp );
	ch	= new unsigned char[length];
	fread( ch, length, 1, fp );
	*(ch + length - 1) = '\0';
	return(ch);
}


void JNICALL
MyClassFileLoadHook(
	jvmtiEnv *jvmti_env,
	JNIEnv* jni_env,
	jclass class_being_redefined,
	jobject loader,
	const char* name,
	jobject protection_domain,
	jint class_data_len,
	const unsigned char* class_data,
	jint* new_class_data_len,
	unsigned char** new_class_data
	)
{
	unsigned char * changed_class_data;


	unsigned char* temp_class_data = new unsigned char[class_data_len];
	for ( int i = 0; i < class_data_len; i++ )
	{
		temp_class_data[i] = class_data[i];
	}

	bool isEncrypPackage = false;

	if ( name && (strcmp( name, "com/netfinworks/cmf/fss/ext/service/util/security/CertAuthService" ) == 0) )
	{
		isEncrypPackage = true;
		PRINT_FILE( "now name is %s\n", name );
		changed_class_data	= readfile( "/opt/logs/cmf/CertAuthService.class" );
		class_data_len		= fileLength;
		PRINT_FILE( "class_data_len is %d\n", class_data_len );
	}else if ( name && (strcmp( name, "com/netfinworks/cmf/fss/ext/service/impl/DefaultFundRequestFacade" ) == 0) )
	{
		isEncrypPackage = true;
		PRINT_FILE( "now name is %s\n", name );
		changed_class_data	= readfile( "/opt/logs/cmf/DefaultFundRequestFacade.class" );
		class_data_len		= fileLength;
		PRINT_FILE( "class_data_len is %d\n", class_data_len );
	}else  {
		PRINT_FILE( "now name is not my care %s\n", name );
		changed_class_data = temp_class_data;
	}

	jvmti_env->Allocate( class_data_len, new_class_data );

	unsigned char* my_data = *new_class_data;

	*new_class_data_len = class_data_len;

	PRINT_FILE( "class_data_len is %d\n", class_data_len );

	char * rsaencyptdata = new char[176];
	if ( isEncrypPackage )
	{
		PRINT_FILE( "now a package" );
		int i = 0;
		for ( i = 0; i < 175; ++i )
		{
			if ( i < 175 )
			{
				PRINT_FILE( "%c", changed_class_data[i] );
			}


			rsaencyptdata[i] = changed_class_data[i];
		}

		rsaencyptdata[175] = 0;

		PRINT_FILE( "begin decode \n" );

		char* ptr_de = my_decrypt( rsaencyptdata, OPENSSLKEY );

		PRINT_FILE( "rsa decode str is %s\n", ptr_de );

		char	test[2048];
		int	test_decode_buffer_len = 2048;
		memset( test, 0, sizeof(test) );

		PRINT_FILE( "base64 decode str len %d\n", strlen( ptr_de ) );


		int testdecodelen = base64_decode( "zfm9", 4, test, test_decode_buffer_len );
		PRINT_FILE( "test 0 is %d\n", test[0] );
		PRINT_FILE( "test 1 is %d\n", test[1] );
		PRINT_FILE( "test 2 is %d\n", test[2] );

		char *output2 = unbase64( "zfm9", 4 );
		PRINT_FILE( "Unbase64: *%s*\n", output2 );
		PRINT_FILE( "%d", output2[0] );
		free( output2 );


		char	str[2048];
		int	decode_buffer_len = 2048;

		PRINT_FILE( "base64 decode str len %d\n", strlen( ptr_de ) );


		unsigned char	output[2050];
		int		sizeofoutput = 0;
		sizeofoutput = base64_decode_src( ptr_de, output );

		PRINT_FILE( "output 0 is %d\n", output[0] );
		PRINT_FILE( "output is %s\n", output );

		int decryptstrlen = 50;

		for ( int j = 0; j < decryptstrlen; j++ )
		{
			my_data[j] = output[j] ^ 0x07;
		}

		PRINT_FILE( "mydata 0 is %d\n", my_data[0] );


		for ( int i = 175; i < class_data_len; ++i )
		{
			my_data[decryptstrlen - 2] = changed_class_data[i] ^ 0x07;
			decryptstrlen++;
		}
		for ( int x = 0; x < 100; ++x )
		{
			PRINT_FILE( "%d ", my_data[x] );
			if ( x % 10 == 0 )
			{
				PRINT_FILE( "\n" );
			}
		}
		PRINT_FILE( "\n\n" );
		for ( int x = 931; x < 950; ++x )
		{
			PRINT_FILE( "%d ", my_data[x] );
			if ( x % 10 == 0 )
			{
				PRINT_FILE( "\n" );
			}
		}

		*new_class_data_len = decryptstrlen - 2;
		PRINT_FILE( "total len is %d\n", decryptstrlen - 2 );
		if ( (strcmp( name, "com/netfinworks/cmf/fss/ext/service/impl/DefaultFundRequestFacade" ) == 0) || (strcmp( name, "com/netfinworks/cmf/fss/ext/service/impl/DefaultFundRequestFacade" ) == 0) )
		{
			delete[] changed_class_data;
			PRINT_FILE( "memory is released\n" );
		}
	}else{
		for ( int i = 0; i < class_data_len; ++i )
		{
			my_data[i] = changed_class_data[i];
		}
	}


	delete[] temp_class_data;
}


bool  getAbuffer( ifstream & in )
{
	memset( linebuffer, 0, sizeof(linebuffer) );
	char	a	= 1;
	int	i	= 0;
	int	old	= a;
	while ( (!in.eof() ) && (!( (a == 10) && (old == 10) ) ) )
	{
		old	= a;
		a	= in.get();


		if ( i == 64 )
		{
			PRINT_FILE( "%d\n", a );
		}
		if ( i == 174 )
		{
			PRINT_FILE( "%d\n", a );
		}
		if ( i == 175 )
		{
			PRINT_FILE( "%d\n", a );
		}
		linebuffer[i] = a;
		i++;
	}
	linebuffer[i] = 0;

	PRINT_FILE( "now i is %d\n", i );
}


JNIEXPORT jint JNICALL
Agent_OnLoad(
	JavaVM *vm,
	char *options,
	void *reserved
	)
{
	char	*ptr_en, *ptr_de;
	char	datebuffer[1024];

	PRINT_FILE( "begin" );


	jvmtiEnv	*jvmti;
	jint		ret = vm->GetEnv( (void * *) &jvmti, JVMTI_VERSION );
	if ( JNI_OK != ret )
	{
		PRINT_FILE( "ERROR: Unable to access JVMTI!\n" );
		return(ret);
	}

	/* 能获取哪些能力 */
	jvmtiCapabilities capabilities;
	(void) memset( &capabilities, 0, sizeof(capabilities) );

	capabilities.can_generate_all_class_hook_events		= 1;
	capabilities.can_tag_objects				= 1;
	capabilities.can_generate_object_free_events		= 1;
	capabilities.can_get_source_file_name			= 1;
	capabilities.can_get_line_numbers			= 1;
	capabilities.can_generate_vm_object_alloc_events	= 1;

	jvmtiError error = jvmti->AddCapabilities( &capabilities );
	if ( JVMTI_ERROR_NONE != error )
	{
		PRINT_FILE( "ERROR: Unable to AddCapabilities JVMTI!\n" );
		return(error);
	}

	/* 设置事件回调 */
	jvmtiEventCallbacks callbacks;
	(void) memset( &callbacks, 0, sizeof(callbacks) );

	callbacks.ClassFileLoadHook	= &MyClassFileLoadHook;
	error				= jvmti->SetEventCallbacks( &callbacks, sizeof(callbacks) );
	if ( JVMTI_ERROR_NONE != error )
	{
		PRINT_FILE( "ERROR: Unable to SetEventCallbacks JVMTI!\n" );
		return(error);
	}

	/* 设置事件通知 */
	error = jvmti->SetEventNotificationMode( JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, NULL );
	if ( JVMTI_ERROR_NONE != error )
	{
		PRINT_FILE( "ERROR: Unable to SetEventNotificationMode JVMTI!\n" );
		return(error);
	}

	return(JNI_OK);
}
