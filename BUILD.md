## Directory Layout

```
.
├── README.md
└── src
    ├── Makefile
    └── draft-yang-tls-tls13-sm-suites-00.md
```

Description:

* `README.md`: This file...
* `src/Makefile`: Makefile used to build draft
* `src/draft-yang-tls-tls13-sm-suites-00.md`: The draft in markdown format

## Environment

To build the normative RFC draft document, you need to install several helper tools on your local computer. At current stage we only need to build the document on Mac.

This draft is prepared in markdown format so we need a very cool tool called `kramdown-rfc2629`, which you can found at: [kramdown-rfc2629](https://github.com/cabo/kramdown-rfc2629), to convert the markdown into proper format thus tools provisioned by IETF could work smoothly.

The idea behind this is you write the draft in markdown and then use `kramdown-rfc2629` to turn the markdown doc into valid RFC-compatible XML file. Once you get the XML file ready, you need to use another tool called `xml2rfc` to convert the raw XML file into a human readable style, like TXT, HTML, etc.

Besides, IETF also provides a nit-checking tool called `idnits` for the RFC draft writers to check if there are any nits in the draft before submitting it to IETF working group.

So on a Mac computer, you need to install them as follows:

```
gem install kramdown-rfc2629
brew install idnits
easy_install pip
pip install xml2rfc
```

For the ones whose Mac has a low version `six` package in the original Mac python installation, you can update the `six` package as follows:

```
1. Download the latest `six` package
2. Use this command to install it: python setup.py install
```

This will install the new version of six into another location which is prior in the search path than the Mac-shipped one.

## Build

To build the draft, just simply execute:

```
cd src
make
```

This will generate two new files, in plain text and HTML format respectively.

You can use `make clean` to remove the files built by `make`.

## Check Nits

After edting the draft markdown file, you should always check if there are any nits in the draft by using `idnits`.

You can just simply run `make nits`, and get a `.nits` suffixed file (like `draft-yang-tls-tls13-chinese-suites-00.nits`) in which the content is similar to:

```
draft-yang-tls-tls13-chinese-suites-00.txt:

  Checking boilerplate required by RFC 5378 and the IETF Trust (see
  https://trustee.ietf.org/license-info):
  ----------------------------------------------------------------------------

     No issues found here.

  Checking nits according to https://www.ietf.org/id-info/1id-guidelines.txt:
  ----------------------------------------------------------------------------

     No issues found here.

  Checking nits according to https://www.ietf.org/id-info/checklist :
  ----------------------------------------------------------------------------

     No issues found here.

  Miscellaneous warnings:
  ----------------------------------------------------------------------------

  == Couldn't figure out when the document was first submitted -- there may
     comments or warnings related to the use of a disclaimer for pre-RFC5378
     work that could not be issued because of this.  Please check the Legal
     Provisions document at https://trustee.ietf.org/license-info to determine
     if you need the pre-RFC5378 disclaimer.


  Checking references for intended status: Informational
  ----------------------------------------------------------------------------

  == Missing Reference: 'RFCXXXX' is mentioned on line 833, but not defined
     '|  136 | 4.08 Request Entity Incomplete | [RFCXXXX] |...'

  == Outdated reference: draft-ietf-core-coap has been published as RFC 7252

  ** Obsolete normative reference: RFC 2616 (Obsoleted by RFC 7230, RFC 7231,
     RFC 7232, RFC 7233, RFC 7234, RFC 7235)


     Summary: 1 error (**), 0 flaws (~~), 3 warnings (==), 0 comments (--).
```

All nits picked up by `make nits` should be fixed before submitting the draft to IETF.

## Read the Docs

`open draft-yang-tls-tls13-sm-suites.txt`

or

`open draft-yang-tls-tls13-sm-suites.html`

You can also use `make open` to open the text draft file.
