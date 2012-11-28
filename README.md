dcm4che-3.x
===========
Sources: https://github.com/dcm4che/dcm4che  
Binaries: https://sourceforge.net/projects/dcm4che/files/dcm4che3
Issue Tracker: http://www.dcm4che.org/jira/browse/LIB  

DICOM library and utilities.

This is a complete rewrite of [dcm4che-2.x](http://www.dcm4che.org/confluence/display/d2/).

One main focus was to minimize the memory footprint of the DICOM data sets.
It already provides modules to store/fetch configuration data to/from LDAP,
compliant to the DICOM Application Configuration Management Profile,
specified in [DICOM 2011, Part 15][1], Annex H.

[1]: ftp://medical.nema.org/medical/dicom/2011/11_15pu.pdf

There are still gaps compared to the functionality of dcm4che-2.x:

- no compression/decompression
- no IIO Image Reader/Writer implementation for DICOM images
- no DICOM Image rendering support
- no DICOM Hanging Protocol support
- no Audit log message support

In long term, 3.x will provide the functionality of 2.x.

Build
-----
After installation of [Maven 3](http://maven.apache.org):

    > mvn install

Modules
-------
- dcm4che-core
- dcm4che-net
- dcm4che-conf
  - dcm4che-conf-api
  - dcm4che-conf-ldap
  - dcm4che-conf-ldap-hl7
  - dcm4che-conf-prefs
  - dcm4che-conf-prefs-hl7
- dcm4che-soundex
- dcm4che-jboss-modules
- dcm4che-servlet

Utilities
---------
- [dcm2xml](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-dcm2xml/README.md)
- [dcmdump](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-dcmdump/README.md)
- [dcmdir](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-dcmdir/README.md)
- [dcmqrscp](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-dcmqrscp/README.md)
- [findscu](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-findscu/README.md)
- [getscu](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-getscu/README.md)
- [hl72xml](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-hl72xml/README.md)
- [hl7pix](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-hl7pix/README.md)
- [hl7rcv](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-hl7rcv/README.md)
- [hl7snd](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-hl7snd/README.md)
- [ianscp](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-ianscp/README.md)
- [ianscu](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-ianscu/README.md)
- [mkkos](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-mkkos/README.md)
- [modality](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-ihe/dcm4che-tool-ihe-modality/README.md)
- [movescu](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-movescu/README.md)
- [mppsscp](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-mppsscp/README.md)
- [mppsscu](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-mppsscu/README.md)
- [stgcmtscu](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-stgcmtscu/README.md)
- [storescp](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-storescp/README.md)
- [storescu](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-storescu/README.md)
- [xml2dcm](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-xml2dcm/README.md)
- [xml2hl7](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-xml2hl7/README.md)
- [xml2prefs](https://github.com/dcm4che/dcm4che/blob/master/dcm4che-tool/dcm4che-tool-xml2prefs/README.md)

License
-------
* [Mozilla Public License Version 1.1](http://www.mozilla.org/MPL/1.1/)

