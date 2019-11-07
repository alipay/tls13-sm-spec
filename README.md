# SM Cipher Suites for TLSv1.3

The repository hosts the IETF Internet-Draft (I-D) of Chinese cipher suites in TLSv1.3 and related documentation.

The I-D specifies a method of applying SM cipher suites within Transport Layer Security protocol version 1.3.

It's appreciated to have more organizations as well as individuals to co-operate on this I-D.

## The Draft

Following what IETF requires, the draft's named as: [draft-yang-tls-tls13-sm-suites](https://tools.ietf.org/html/draft-yang-tls-tls13-sm-suites-01)

Reference to different formats of the compiled draft:

* [TXT](https://tools.ietf.org/id/draft-yang-tls-tls13-sm-suites-00.txt)
* [HTML](https://tools.ietf.org/html/draft-yang-tls-tls13-sm-suites-00)

Data Tracker on IETF: [https://datatracker.ietf.org/doc/draft-yang-tls-tls13-sm-suites/](https://datatracker.ietf.org/doc/draft-yang-tls-tls13-sm-suites/)

## Participation

Both the official IETF [TLS WG mailing list](https://www.ietf.org/mailman/listinfo/tls) and the [Issues](https://github.com/alipay/tls13-sm-spec/issues) section of this repository would be nice places for any comments or discussions.

## Build the Draft

Read the [BUILD.md](./BUILD.md) file for information on directory layout and building method.

## Chinese Algorithm Standards

In this draft, some Chinese SM algorithm specifications are referenced. Not all of them are freely available online, so we offer some free English version here.

There are several standard organizations have already published or are publishing SM related specifications:

* CSTC (Cryptography Standardization Technical Committee), publishes the `GM/T` prefixed standards, which are the original SM algorithm specifications.
* NISSTC (National Information Security Standardization Technical Committee), is in charge of turning `GM/T` files into `GB/T` files. So they are identical to each other from the aspect of content, except the names of the published standards are different. NISSTC is more normative than CSTC from a legal point of view.
* ISO (International Organization for Standardization), has published SM2, SM3 and SM9 in different ISO files. SM4 is now on its process to be included in.

The following table can be used to sort out the relations between different specification files.

|SM Algorithms|CSTC|NISSTC|ISO|
|-------------|----|------|---|
|SM2|GM/T 0003.1-2012<br>GM/T 0003.2-2012<br>GM/T 0003.3-2012<br>GM/T 0003.4-2012<br>GM/T 0003.5-2012<br>Free in Chinese|[GB/T 32918.1-2016](sm-en-pdfs/sm2/GBT.32918.1-2016.SM2-en.pdf)([Download](https://github.com/alipay/tls13-sm-spec/raw/master/sm-en-pdfs/sm2/GBT.32918.1-2016.SM2-en.pdf))<br>[GB/T 32918.2-2016](sm-en-pdfs/sm2/GBT.32918.2-2016.SM2-en.pdf)([Download](https://github.com/alipay/tls13-sm-spec/raw/master/sm-en-pdfs/sm2/GBT.32918.2-2016.SM2-en.pdf))<br>[GB/T 32918.3-2016](sm-en-pdfs/sm2/GBT.32918.3-2016.SM2-en.pdf)([Download](https://github.com/alipay/tls13-sm-spec/raw/master/sm-en-pdfs/sm2/GBT.32918.3-2016.SM2-en.pdf))<br>[GB/T 32918.4-2016](sm-en-pdfs/sm2/GBT.32918.4-2016.SM2-en.pdf)([Download](https://github.com/alipay/tls13-sm-spec/raw/master/sm-en-pdfs/sm2/GBT.32918.4-2016.SM2-en.pdf))<br>[GB/T 32918.5-2016](sm-en-pdfs/sm2/GBT.32918.5-2016.SM2-en.pdf)([Download](https://github.com/alipay/tls13-sm-spec/raw/master/sm-en-pdfs/sm2/GBT.32918.5-2016.SM2-en.pdf))<br>Free in Chinese and English<br>(Download English versions from above links)|ISO/IEC 14888-3:2018<br>(Covers only GB/T 32918.2-2016)<br>Paid, in English|
|SM2 Additional Usage|GM/T 0009-2012<br>Free in Chinese|GB/T 35276-2017<br>Free in Chinese|N/A|
|SM3|GM/T 0004-2012<br>Free in Chinese|[GB/T 32905-2016](sm-en-pdfs/sm3/GBT.32905-2016.SM3-en.pdf)([Download](https://github.com/alipay/tls13-sm-spec/raw/master/sm-en-pdfs/sm3/GBT.32905-2016.SM3-en.pdf))<br>Free in Chinese and English<br>(Download English versions from above links)|ISO ISO/IEC 10118-3:2018<br>Paid, in English|
|SM4|GM/T 0002-2012<br>Free in Chinese|[GB/T 32907-2016](sm-en-pdfs/sm4/GBT.32907-2016.SM4-en.pdf)([Download](https://github.com/alipay/tls13-sm-spec/raw/master/sm-en-pdfs/sm4/GBT.32907-2016.SM4-en.pdf))<br>Free in Chinese and English<br>(Download English versions from above links)|ISO/IEC 18038-3:2010 and Amd2<br>Paid, in English|

*Note: as mentioned, GM/Ts' and GB/Ts' contents are identical to each other except minor naming difference*

*When working for Sun Microsystem, Whitfield Diffie has also done a translation of SM4 specification time ago, we upload the version [here](https://github.com/alipay/tls13-sm-spec/raw/master/sm-en-pdfs/sm4/diffie-sm4.pdf) for your reference.*

We almost have all necessary English specifications here in the table. The current missing one is GM/T 0009-2012 (a.k.a., GB/T 35276-2017), we are now figuring out this missing and will update the table above if there is any update.
