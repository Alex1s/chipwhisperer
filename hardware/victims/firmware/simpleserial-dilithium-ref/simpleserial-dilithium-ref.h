#define MAX_PAYLOAD_LENGTH (249)

#define CMD_SET_KEY ('k')
#define CMD_SET_ALG ('q')
#define CMD_SET_SEED ('s')

#define SUBCOMMAND_LENGTH (255 - 1)
#define SUBCOMMAND_COMMIT (255)
#define KEY_LEN_LEN (1)

#define BUFFER_OVERFLOW (0x10)
#define INVALID_SUBCOMMAND (0x11)
#define INVALID_KEY_LEN_LEN (0x12)
#define INVALID_KEY_LEN (0x12)

#define ASSERT_FAILED (0x31)

#define ASSERT_CMD (0x20)

#define CMD_ALG (0x03)
