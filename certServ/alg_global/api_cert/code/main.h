#pragma once

class main
{
public:
    main() {}
    ~main() {}

private:

};




int testP12Pase()
{
    CP12parse p12(p12file, "1234");
    if(false == p12.isValid()) {
        LOG_E("load p12 file file");
    }
    RsaPrikey_t pri;
    RsaPubkey_t pub;
    unsigned char tbuff[2048];
    int tbufflen=sizeof(tbuff);
    p12.getCert(tbuff, &tbufflen);
    HEXDUMP("cert", tbuff, tbufflen);
    p12.getRsaKey(&pub, &pri);
    HEXDUMP("pubkey", pub.m, (int)sizeof(pub.m));
    HEXDUMP("prikey", pri.p, (int)sizeof(pri.p));
    return 0;

    /*  证书写入文件 */
    fp=fopen(p12ExtCert,"wb");
    fwrite(tbuff, 1, tbufflen, fp);
    fclose(fp);
}











