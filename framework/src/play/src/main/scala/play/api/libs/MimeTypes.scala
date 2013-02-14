package play.api.libs

/**
 * MIME type utilities.
 */
object MimeTypes {

  /**
   * Retrieves the usual MIME type for a given extension.
   *
   * @param ext the file extension, e.g. `txt`
   * @return the MIME type, if defined
   */
  def forExtension(ext: String): Option[String] = types.get(ext)

  /**
   * Retrieves the usual MIME type for a given file name
   *
   * @param name the file name, e.g. `hello.txt`
   * @return the MIME type, if defined
   */
  def forFileName(name: String) = name.split('.').takeRight(1).headOption.flatMap(forExtension(_))

  def types: Map[String, String] = defaultTypes ++ applicationTypes

  /**
   * Mimetypes defined in the current application, as declared in application.conf
   */
  def applicationTypes: Map[String, String] = play.api.Play.maybeApplication.flatMap { application =>
    application.configuration.getConfig("mimetype").map { config =>
      config.subKeys.map { key =>
        (key, config.getString(key))
      }.collect {
        case ((key, Some(value))) =>
          (key, value)
      }.toMap
    }
  }.getOrElse(Map.empty)
  
  /**
   * tells you if mimeType is text or not.
   * Useful to determine whether the charset suffix should be attached to Content-Type or not 
   * @param mimeType mimeType to check
   * @return true if mimeType is text
   */
  def isText(mimeType: String): Boolean = {
    mimeType.trim match {
        case text if text.startsWith("text/") => true
        case text if additionalText.contains(text) => true
        case _ => false
    }
  }

  lazy val defaultTypes =
    """
        3dm=x-world/x-3dmf
        3dmf=x-world/x-3dmf
        7z=application/x-7z-compressed
        a=application/octet-stream
        aab=application/x-authorware-bin
        aam=application/x-authorware-map
        aas=application/x-authorware-seg
        abc=text/vndabc
        ace=application/x-ace-compressed
        acgi=text/html
        afl=video/animaflex
        ai=application/postscript
        aif=audio/aiff
        aifc=audio/aiff
        aiff=audio/aiff
        aim=application/x-aim
        aip=text/x-audiosoft-intra
        alz=application/x-alz-compressed
        ani=application/x-navi-animation
        aos=application/x-nokia-9000-communicator-add-on-software
        aps=application/mime
        arc=application/x-arc-compressed
        arj=application/arj
        art=image/x-jg
        asf=video/x-ms-asf
        asm=text/x-asm
        asp=text/asp
        asx=application/x-mplayer2
        au=audio/basic
        avi=video/x-msvideo
        avs=video/avs-video
        bcpio=application/x-bcpio
        bin=application/mac-binary
        bmp=image/bmp
        boo=application/book
        book=application/book
        boz=application/x-bzip2
        bsh=application/x-bsh
        bz2=application/x-bzip2
        bz=application/x-bzip
        c++=text/plain
        c=text/x-c
        cab=application/vnd.ms-cab-compressed
        cat=application/vndms-pkiseccat
        cc=text/x-c
        ccad=application/clariscad
        cco=application/x-cocoa
        cdf=application/cdf
        cer=application/pkix-cert
        cha=application/x-chat
        chat=application/x-chat
        chrt=application/vnd.kde.kchart
        class=application/java
        # ? class=application/java-vm
        com=text/plain
        conf=text/plain
        cpio=application/x-cpio
        cpp=text/x-c
        cpt=application/mac-compactpro
        crl=application/pkcs-crl
        crt=application/pkix-cert
        crx=application/x-chrome-extension
        csh=text/x-scriptcsh
        css=text/css
        csv=text/csv
        cxx=text/plain
        dar=application/x-dar
        dcr=application/x-director
        deb=application/x-debian-package
        deepv=application/x-deepv
        def=text/plain
        der=application/x-x509-ca-cert
        dif=video/x-dv
        dir=application/x-director
        divx=video/divx
        dl=video/dl
        dmg=application/x-apple-diskimage
        doc=application/msword
        dot=application/msword
        dp=application/commonground
        drw=application/drafting
        dump=application/octet-stream
        dv=video/x-dv
        dvi=application/x-dvi
        dwf=drawing/x-dwf=(old)
        dwg=application/acad
        dxf=application/dxf
        dxr=application/x-director
        el=text/x-scriptelisp
        elc=application/x-bytecodeelisp=(compiled=elisp)
        eml=message/rfc822
        env=application/x-envoy
        eot=application/vnd.ms-fontobject
        eps=application/postscript
        es=application/x-esrehber
        etx=text/x-setext
        evy=application/envoy
        exe=application/octet-stream
        f77=text/x-fortran
        f90=text/x-fortran
        f=text/x-fortran
        fdf=application/vndfdf
        fif=application/fractals
        fli=video/fli
        flo=image/florian
        flv=video/x-flv
        flx=text/vndfmiflexstor
        fmf=video/x-atomic3d-feature
        for=text/x-fortran
        fpx=image/vndfpx
        frl=application/freeloader
        funk=audio/make
        g3=image/g3fax
        g=text/plain
        gif=image/gif
        gl=video/gl
        gsd=audio/x-gsm
        gsm=audio/x-gsm
        gsp=application/x-gsp
        gss=application/x-gss
        gtar=application/x-gtar
        gz=application/x-compressed
        gzip=application/x-gzip
        h=text/x-h
        hdf=application/x-hdf
        help=application/x-helpfile
        hgl=application/vndhp-hpgl
        hh=text/x-h
        hlb=text/x-script
        hlp=application/hlp
        hpg=application/vndhp-hpgl
        hpgl=application/vndhp-hpgl
        hqx=application/binhex
        hta=application/hta
        htc=text/x-component
        htm=text/html
        html=text/html
        htmls=text/html
        htt=text/webviewhtml
        htx=text/html
        ice=x-conference/x-cooltalk
        ico=image/x-icon
        ics=text/calendar
        icz=text/calendar
        idc=text/plain
        ief=image/ief
        iefs=image/ief
        iges=application/iges
        igs=application/iges
        ima=application/x-ima
        imap=application/x-httpd-imap
        inf=application/inf
        ins=application/x-internett-signup
        ip=application/x-ip2
        isu=video/x-isvideo
        it=audio/it
        iv=application/x-inventor
        ivr=i-world/i-vrml
        ivy=application/x-livescreen
        jam=audio/x-jam
        jav=text/x-java-source
        java=text/x-java-source
        jcm=application/x-java-commerce
        jfif-tbnl=image/jpeg
        jfif=image/jpeg
        jnlp=application/x-java-jnlp-file
        jpe=image/jpeg
        jpeg=image/jpeg
        jpg=image/jpeg
        jps=image/x-jps
        js=application/javascript
        json=application/json
        jut=image/jutvision
        kar=audio/midi
        karbon=application/vnd.kde.karbon
        kfo=application/vnd.kde.kformula
        flw=application/vnd.kde.kivio
        kml=application/vnd.google-earth.kml+xml
        kmz=application/vnd.google-earth.kmz
        kon=application/vnd.kde.kontour
        kpr=application/vnd.kde.kpresenter
        kpt=application/vnd.kde.kpresenter
        ksp=application/vnd.kde.kspread
        kwd=application/vnd.kde.kword
        kwt=application/vnd.kde.kword
        ksh=text/x-scriptksh
        la=audio/nspaudio
        lam=audio/x-liveaudio
        latex=application/x-latex
        lha=application/lha
        lhx=application/octet-stream
        list=text/plain
        lma=audio/nspaudio
        log=text/plain
        lsp=text/x-scriptlisp
        lst=text/plain
        lsx=text/x-la-asf
        ltx=application/x-latex
        lzh=application/octet-stream
        lzx=application/lzx
        m1v=video/mpeg
        m2a=audio/mpeg
        m2v=video/mpeg
        m3u=audio/x-mpegurl
        m=text/x-m
        man=application/x-troff-man
        manifest=text/cache-manifest
        map=application/x-navimap
        mar=text/plain
        mbd=application/mbedlet
        mc$=application/x-magic-cap-package-10
        mcd=application/mcad
        mcf=text/mcf
        mcp=application/netmc
        me=application/x-troff-me
        mht=message/rfc822
        mhtml=message/rfc822
        mid=application/x-midi
        midi=application/x-midi
        mif=application/x-frame
        mime=message/rfc822
        mjf=audio/x-vndaudioexplosionmjuicemediafile
        mjpg=video/x-motion-jpeg
        mm=application/base64
        mme=application/base64
        mod=audio/mod
        moov=video/quicktime
        mov=video/quicktime
        movie=video/x-sgi-movie
        mp2=audio/mpeg
        mp3=audio/mpeg
        mp4=video/mp4
        mpa=audio/mpeg
        mpc=application/x-project
        mpe=video/mpeg
        mpeg=video/mpeg
        mpg=video/mpeg
        mpga=audio/mpeg
        mpp=application/vndms-project
        mpt=application/x-project
        mpv=application/x-project
        mpx=application/x-project
        mrc=application/marc
        ms=application/x-troff-ms
        mv=video/x-sgi-movie
        my=audio/make
        mzz=application/x-vndaudioexplosionmzz
        nap=image/naplps
        naplps=image/naplps
        nc=application/x-netcdf
        ncm=application/vndnokiaconfiguration-message
        nif=image/x-niff
        niff=image/x-niff
        nix=application/x-mix-transfer
        nsc=application/x-conference
        nvd=application/x-navidoc
        o=application/octet-stream
        oda=application/oda
        odb=application/vnd.oasis.opendocument.database
        odc=application/vnd.oasis.opendocument.chart
        odf=application/vnd.oasis.opendocument.formula
        odg=application/vnd.oasis.opendocument.graphics
        odi=application/vnd.oasis.opendocument.image
        odm=application/vnd.oasis.opendocument.text-master
        odp=application/vnd.oasis.opendocument.presentation
        ods=application/vnd.oasis.opendocument.spreadsheet
        odt=application/vnd.oasis.opendocument.text
        oga=audio/ogg
        ogg=audio/ogg
        ogv=video/ogg
        omc=application/x-omc
        omcd=application/x-omcdatamaker
        omcr=application/x-omcregerator
        otc=application/vnd.oasis.opendocument.chart-template
        otf=application/vnd.oasis.opendocument.formula-template
        otg=application/vnd.oasis.opendocument.graphics-template
        oth=application/vnd.oasis.opendocument.text-web
        oti=application/vnd.oasis.opendocument.image-template
        otm=application/vnd.oasis.opendocument.text-master
        otp=application/vnd.oasis.opendocument.presentation-template
        ots=application/vnd.oasis.opendocument.spreadsheet-template
        ott=application/vnd.oasis.opendocument.text-template
        p10=application/pkcs10
        p12=application/pkcs-12
        p7a=application/x-pkcs7-signature
        p7c=application/pkcs7-mime
        p7m=application/pkcs7-mime
        p7r=application/x-pkcs7-certreqresp
        p7s=application/pkcs7-signature
        p=text/x-pascal
        part=application/pro_eng
        pas=text/pascal
        pbm=image/x-portable-bitmap
        pcl=application/vndhp-pcl
        pct=image/x-pict
        pcx=image/x-pcx
        pdb=chemical/x-pdb
        pdf=application/pdf
        pfunk=audio/make
        pgm=image/x-portable-graymap
        pic=image/pict
        pict=image/pict
        pkg=application/x-newton-compatible-pkg
        pko=application/vndms-pkipko
        pl=text/x-scriptperl
        plx=application/x-pixclscript
        pm4=application/x-pagemaker
        pm5=application/x-pagemaker
        pm=text/x-scriptperl-module
        png=image/png
        pnm=application/x-portable-anymap
        pot=application/mspowerpoint
        pov=model/x-pov
        ppa=application/vndms-powerpoint
        ppm=image/x-portable-pixmap
        pps=application/mspowerpoint
        ppt=application/mspowerpoint
        ppz=application/mspowerpoint
        pre=application/x-freelance
        prt=application/pro_eng
        ps=application/postscript
        psd=application/octet-stream
        pvu=paleovu/x-pv
        pwz=application/vndms-powerpoint
        py=text/x-scriptphyton
        pyc=applicaiton/x-bytecodepython
        qcp=audio/vndqcelp
        qd3=x-world/x-3dmf
        qd3d=x-world/x-3dmf
        qif=image/x-quicktime
        qt=video/quicktime
        qtc=video/x-qtc
        qti=image/x-quicktime
        qtif=image/x-quicktime
        ra=audio/x-pn-realaudio
        ram=audio/x-pn-realaudio
        rar=application/x-rar-compressed
        ras=application/x-cmu-raster
        rast=image/cmu-raster
        rdf=application/rdf+xml
        rexx=text/x-scriptrexx
        rf=image/vndrn-realflash
        rgb=image/x-rgb
        rm=application/vndrn-realmedia
        rmi=audio/mid
        rmm=audio/x-pn-realaudio
        rmp=audio/x-pn-realaudio
        rng=application/ringing-tones
        rnx=application/vndrn-realplayer
        roff=application/x-troff
        rp=image/vndrn-realpix
        rpm=audio/x-pn-realaudio-plugin
        rt=text/vndrn-realtext
        rtf=text/richtext
        rtx=text/richtext
        rv=video/vndrn-realvideo
        s=text/x-asm
        s3m=audio/s3m
        s7z=application/x-7z-compressed
        saveme=application/octet-stream
        sbk=application/x-tbook
        scm=text/x-scriptscheme
        sdml=text/plain
        sdp=application/sdp
        sdr=application/sounder
        sea=application/sea
        set=application/set
        sgm=text/x-sgml
        sgml=text/x-sgml
        sh=text/x-scriptsh
        shar=application/x-bsh
        shtml=text/x-server-parsed-html
        sid=audio/x-psid
        skd=application/x-koan
        skm=application/x-koan
        skp=application/x-koan
        skt=application/x-koan
        sit=application/x-stuffit
        sitx=application/x-stuffitx
        sl=application/x-seelogo
        smi=application/smil
        smil=application/smil
        snd=audio/basic
        sol=application/solids
        spc=text/x-speech
        spl=application/futuresplash
        spr=application/x-sprite
        sprite=application/x-sprite
        spx=audio/ogg
        src=application/x-wais-source
        ssi=text/x-server-parsed-html
        ssm=application/streamingmedia
        sst=application/vndms-pkicertstore
        step=application/step
        stl=application/sla
        stp=application/step
        sv4cpio=application/x-sv4cpio
        sv4crc=application/x-sv4crc
        svf=image/vnddwg
        svg=image/svg+xml
        svr=application/x-world
        swf=application/x-shockwave-flash
        t=application/x-troff
        talk=text/x-speech
        tar=application/x-tar
        tbk=application/toolbook
        tcl=text/x-scripttcl
        tcsh=text/x-scripttcsh
        tex=application/x-tex
        texi=application/x-texinfo
        texinfo=application/x-texinfo
        text=text/plain
        tgz=application/gnutar
        tif=image/tiff
        tiff=image/tiff
        tr=application/x-troff
        tsi=audio/tsp-audio
        tsp=application/dsptype
        tsv=text/tab-separated-values
        turbot=image/florian
        ttl=text/turtle
        txt=text/plain
        uil=text/x-uil
        uni=text/uri-list
        unis=text/uri-list
        unv=application/i-deas
        uri=text/uri-list
        uris=text/uri-list
        ustar=application/x-ustar
        uu=text/x-uuencode
        uue=text/x-uuencode
        vcd=application/x-cdlink
        vcf=text/x-vcard
        vcard=text/x-vcard
        vcs=text/x-vcalendar
        vda=application/vda
        vdo=video/vdo
        vew=application/groupwise
        viv=video/vivo
        vivo=video/vivo
        vmd=application/vocaltec-media-desc
        vmf=application/vocaltec-media-file
        voc=audio/voc
        vos=video/vosaic
        vox=audio/voxware
        vqe=audio/x-twinvq-plugin
        vqf=audio/x-twinvq
        vql=audio/x-twinvq-plugin
        vrml=application/x-vrml
        vrt=x-world/x-vrt
        vsd=application/x-visio
        vst=application/x-visio
        vsw=application/x-visio
        w60=application/wordperfect60
        w61=application/wordperfect61
        w6w=application/msword
        wav=audio/wav
        wb1=application/x-qpro
        wbmp=image/vnd.wap.wbmp
        web=application/vndxara
        wiz=application/msword
        wk1=application/x-123
        wmf=windows/metafile
        wml=text/vnd.wap.wml
        wmlc=application/vnd.wap.wmlc
        wmls=text/vnd.wap.wmlscript
        wmlsc=application/vnd.wap.wmlscriptc
        woff=application/x-font-woff
        word=application/msword
        wp5=application/wordperfect
        wp6=application/wordperfect
        wp=application/wordperfect
        wpd=application/wordperfect
        wq1=application/x-lotus
        wri=application/mswrite
        wrl=application/x-world
        wrz=model/vrml
        wsc=text/scriplet
        wsrc=application/x-wais-source
        wtk=application/x-wintalk
        x-png=image/png
        xbm=image/x-xbitmap
        xdr=video/x-amt-demorun
        xgz=xgl/drawing
        xif=image/vndxiff
        xl=application/excel
        xla=application/excel
        xlb=application/excel
        xlc=application/excel
        xld=application/excel
        xlk=application/excel
        xll=application/excel
        xlm=application/excel
        xls=application/excel
        xlt=application/excel
        xlv=application/excel
        xlw=application/excel
        xm=audio/xm
        xml=text/xml
        xmz=xgl/movie
        xpi=application/x-xpinstall
        xpix=application/x-vndls-xpix
        xpm=image/x-xpixmap
        xsr=video/x-amt-showrun
        xwd=image/x-xwd
        xyz=chemical/x-pdb
        z=application/x-compress
        zip=application/zip
        zoo=application/octet-stream
        zsh=text/x-scriptzsh

        # Office 2007 mess - http://wdg.uncc.edu/Microsoft_Office_2007_MIME_Types_for_Apache_and_IIS
        docx=application/vnd.openxmlformats-officedocument.wordprocessingml.document
        docm=application/vnd.ms-word.document.macroEnabled.12
        dotx=application/vnd.openxmlformats-officedocument.wordprocessingml.template
        dotm=application/vnd.ms-word.template.macroEnabled.12
        xlsx=application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
        xlsm=application/vnd.ms-excel.sheet.macroEnabled.12
        xltx=application/vnd.openxmlformats-officedocument.spreadsheetml.template
        xltm=application/vnd.ms-excel.template.macroEnabled.12
        xlsb=application/vnd.ms-excel.sheet.binary.macroEnabled.12
        xlam=application/vnd.ms-excel.addin.macroEnabled.12
        pptx=application/vnd.openxmlformats-officedocument.presentationml.presentation
        pptm=application/vnd.ms-powerpoint.presentation.macroEnabled.12
        ppsx=application/vnd.openxmlformats-officedocument.presentationml.slideshow
        ppsm=application/vnd.ms-powerpoint.slideshow.macroEnabled.12
        potx=application/vnd.openxmlformats-officedocument.presentationml.template
        potm=application/vnd.ms-powerpoint.template.macroEnabled.12
        ppam=application/vnd.ms-powerpoint.addin.macroEnabled.12
        sldx=application/vnd.openxmlformats-officedocument.presentationml.slide
        sldm=application/vnd.ms-powerpoint.slide.macroEnabled.12
        thmx=application/vnd.ms-officetheme 
        onetoc=application/onenote
        onetoc2=application/onenote
        onetmp=application/onenote
        onepkg=application/onenote
        # koffice

        # iWork
        key=application/x-iwork-keynote-sffkey
        kth=application/x-iwork-keynote-sffkth
        nmbtemplate=application/x-iwork-numbers-sfftemplate
        numbers=application/x-iwork-numbers-sffnumbers
        pages=application/x-iwork-pages-sffpages
        template=application/x-iwork-pages-sfftemplate

        # Extensions for Mozilla apps (Firefox and friends)
        xpi=application/x-xpinstall

    """.split('\n').map(_.trim).filter(_.size > 0).filter(_(0) != '#').map(_.split('=')).map(parts =>
      parts(0) -> parts.drop(1).mkString).toMap

    lazy val additionalText =
    """
        application/json
        application/javascript
    """.split('\n').map(_.trim).filter(_.size > 0).filter(_(0) != '#')

}
