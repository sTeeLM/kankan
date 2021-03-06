#!/usr/bin/env python
import zipfile
import os,sys,getopt,re
import xml.dom.minidom
import array

# http://www.duokan.com/store/v0/web/book/xxx

def usage() :
    print"""Usage:
    kankan <command> [<options>] <epubfile>
        list: list content of an epub file
            Options:
            -v | --verbose : verbose output
            -s | --size : sort by size
            -n | --name : sort by name
            -r | --reverse : reverse order when sort
        info: get meta information
            Options:
            -v | verbose : verbose output
        rename: rename epub file
            Options:
            -f | --format : format string
                {title} for title, {contributor} for contributor, {publisher} for publisher, etc.
        analyse: analyse epub file
            Options:
            -e | --encrypted-file : an encrypted file path in epub, for example: "OEBPS/Images/coverpage.jpeg"
            -p | --plain-file : path of plain context of the encrypted file
            -v | --verbose : show target text content
        decrypt: decrypt epub file
            Options:
            -e | --encrypted-file: an encrypted file path in epub, for example: "OEBPS/Images/coverpage.jpeg"
            -p | --plain-file: path of plain context of the encrypted file
            -v | --verbose : print progress
    """

def parse_cmd(argv) :
    cmd_options = {
        'list' : {'opts' : 'vsnr', 'lopts' : ['verbose', 'size', 'name', 'reverse']},
        'info' : {'opts' : 'v', 'lopts' : ['verbose']},
        'rename' : {'opts' : 'f:', 'lopts' : ['format=']},
        'analyse' : {'opts' : 'e:p:v', 'lopts' : ['encrypted-file=', 'plain-file=', 'verbose']},
        'decrypt' : {'opts' : 'e:p:vt', 'lopts' : ['encrypted-file=', 'plain-file=', 'verbose', 'trunk']}
        }
    parsed_options = {
        'verbose' : 0,
        'size' : 1,
        'name' : 0,
        'reverse' : 0,
        'format' : '{title}.epub',
        'encrypted-file' : '',
        'plain-file' : '',
        'epub-file' : '',
		'trunk' : 0
    }
    if len(argv) <= 2:
        usage()
        sys.exit(1)
    if cmd_options.has_key(argv[1]) :
        try:
            opts, args = getopt.getopt(argv[2:], cmd_options[argv[1]]['opts'], cmd_options[argv[1]]['lopts'])
            for opt,arg in opts :
                if opt in ('-v', '--verbose') :
                    parsed_options['verbose'] = 1
                elif opt in ('-s', '--size') :
                    parsed_options['size'] = 1
                    parsed_options['name'] = 0
                elif opt in ('-n', '--name') :
                    parsed_options['size'] = 0
                    parsed_options['name'] = 1
                elif opt in ('-r', '--reverse') :
                    parsed_options['reverse'] = 1
                elif opt in ('-e', '--encrypted-file') :
                    parsed_options['encrypted-file'] = arg
                elif opt in ('-p', '--plain-file') :
                    parsed_options['plain-file'] = arg
                elif opt in ('-f', '--format') :
                    parsed_options['format'] = arg
                elif opt in ('-t', '--trunk') :
                    parsed_options['trunk'] = 1
                else:
                    usage()
                    sys.exit(1)
            if len(args) != 1 :
                usage()
                sys.exit(1)
            else:
                parsed_options['epub-file'] = args[0]
        except getopt.GetoptError:
            usage()
            sys.exit(1)
        return (argv[1], parsed_options)
    else:
        usage()
        sys.exit(1)

def read_epub_file(opts, filename) :
    ret = None
    try:
        with zipfile.ZipFile(opts['epub-file'], 'r') as zip_file :  
            ret = zip_file.read(filename)
    except zipfile.BadZipfile:
        print '%s is not a zip file' % (opts['epub-file'])
        ret = None
    except KeyError:
        print 'no %s in %s' % (filename, opts['epub-file'])
        ret = None
    except IOError:
        print 'error when read %s' % (opts['epub-file'])
        ret = None
    return ret

def list_epub_entries(opts):
    """
    list content of an epub file
    """
    epub_entries = None
    try:
        with zipfile.ZipFile(opts['epub-file'], 'r') as zip_file :
            infos = zip_file.infolist()
            epub_entries = sorted(infos,
                                   key=lambda x : x.file_size if opts['size'] else x.filename,
                                   reverse=opts['reverse'])
    except zipfile.BadZipfile:
        print '%s is not a zip file' % (opts['epub-file'])
        epub_entries = None
    except IOError:
        print 'error when read %s' % (opts['epub-file'])
        epub_entries = None
    return epub_entries

def list_epub(opts) :
    epub_entries = list_epub_entries(opts)
    if epub_entries is None:
        sys.exit(1)
    if opts['verbose'] == 0 :
        print 'size\tname'
        for info in epub_entries :
            print "%d\t%s" % (info.file_size, info.filename)
    else :
        print 'org_size\tcompress_size\ttype\tdate_time\tname'
        for info in epub_entries :
            date_time = '%04d-%02d-%02d %02d:%02d:%02d' % info.date_time
            print "%d\t%d\t%s\t%s\t%s" % (info.file_size, info.compress_size, info.compress_type, date_time, info.filename)
    sys.exit(0)
        
        
def read_epub_meta(opts):
    "read meta info of an epub file"
    epub_meta = {
        'title' : '',
        'creator' : '',
        'publisher' : '',
        'subject' : '',
        'description' : '',
        'contributor' : '',
        'date' : '',
        'type' : '',
        'format' : '',
        'identifier' : {},
        'source' : '',
        'language' : '',
        'relation' : '',
        'coverage' : '',
        'rights' : '',
        'meta' : {}
    }
    opf = read_epub_file(opts, 'OEBPS/content.opf')
    if opf == None :
        opf = read_epub_file(opts, 'OPS/content.opf')
    if opf == None :
        opf = read_epub_file(opts, 'content.opf')       
    if opf == None :
        print "no content.opf found!"
        return None
    dom = xml.dom.minidom.parseString(opf)
    for node in dom.documentElement.getElementsByTagName('metadata')[0].childNodes:
        if node.nodeType == node.ELEMENT_NODE :
            if node.localName != 'identifier' and node.localName != 'meta':
                epub_meta[node.localName] = node.childNodes[0].nodeValue
            elif  node.localName == 'identifier' :
                epub_meta[node.localName][node.getAttribute('id')] = node.childNodes[0].nodeValue
            elif  node.localName == 'meta' :
                epub_meta[node.localName][node.getAttribute('name')] = node.getAttribute('content')
    return epub_meta
    
        
def info_epub(opts):
    """
    get meta info of an epub file
    """
    epub_meta = read_epub_meta(opts)
    if epub_meta == None :
        sys.exit(1)
    if opts['verbose'] :
        for key in epub_meta.keys() :
            if key != 'meta' and key != 'identifier' :
                print '%s: %s' % (key, epub_meta[key])
            elif  key == 'identifier' :
                print 'identifier:'
                for i in epub_meta['identifier'].keys() :
                    print '\t%s:\t%s' % (i, epub_meta['identifier'][i])
            elif  key == 'meta' :
                print 'meta:'
                for i in epub_meta['meta'].keys() :
                    print '\t%s:\t%s' % (i, epub_meta['meta'][i])
                
    else :
        print 'title: %s' % (epub_meta['title'])
        print 'publisher: %s' % (epub_meta['publisher'])
        print 'creator: %s' % (epub_meta['creator'])

def rename_epub(opts) :
    """
    rename epub file
    """
    epub_meta = read_epub_meta(opts)
    if epub_meta == None :
        sys.exit(1)
    new_name = ''
    try :
        new_name = opts['format'].format(
            title       = epub_meta['title'].encode('utf-8'),
            creator     = epub_meta['creator'].encode('utf-8'),
            publisher   = epub_meta['publisher'].encode('utf-8'),
            subject     = epub_meta['subject'].encode('utf-8'),
            description = epub_meta['description'].encode('utf-8'),
            contributor = epub_meta['contributor'].encode('utf-8'),
            date        = epub_meta['date'].encode('utf-8'),
            source      = epub_meta['source'].encode('utf-8'),
            language    = epub_meta['language'].encode('utf-8'),
            relation    = epub_meta['relation'].encode('utf-8'),
            coverage    = epub_meta['coverage'].encode('utf-8'),
            rights      = epub_meta['rights'].encode('utf-8'),
        )
    except KeyError:
        sys.exit(1)
    old_path = os.path.abspath(opts['epub-file'])
    dir_path, old_name = os.path.split(old_path)
    new_path = os.path.join(dir_path ,new_name)
    print "%s => %s" % (old_path, new_path)
    os.rename(old_path, new_path)
    sys.exit(0) 

def gen_key(opts, enc_file, plain_file) :
    key = None
    iv = None
    enc = read_epub_file(opts, enc_file)
    try:
        with open( plain_file, 'rb') as f :
            plain = f.read()
    except IOError:
            plain = None
    if plain == None or enc == None :
        return None
    print "plain size %d" % len(plain)
    print "encrypt size %d" % len(enc)
    # check plain file size
    diff_len = len(enc) - 16 - len(plain)
    if diff_len < 0 or diff_len >= 16 :
        print "plain file size %d mismatch with encrypted one %d , should be [%d %d]" % \
            (len(plain), len(enc), len(enc) - 16 - 15, len(enc) - 16)
        return None
    # make key
    enc = array.array('B', enc)
    plain = array.array('B', plain)
    for i in range(diff_len) :
        plain.append(0)
    key = array.array('B')
    iv  = array.array('B')
    for i in range(len(plain)):
        key.append(plain[i] ^ enc[i+16])
    iv = enc[0:16]
    print 'key size %d' % (len(key))
    print 'iv size %d' % (len(iv))
    return (key, iv)

def read_encryption_xml(opts) :
    encryption_list = {}
    encryption_xml = read_epub_file(opts, 'META-INF/encryption.xml')
    dom = xml.dom.minidom.parseString(encryption_xml)
    for node in dom.documentElement.getElementsByTagName('enc:EncryptedData'):
        if node.nodeType == node.ELEMENT_NODE :
            algorithm = node.getElementsByTagName('enc:EncryptionMethod')[0].getAttribute('Algorithm')
            uri = node.getElementsByTagName('enc:CipherData')[0].getElementsByTagName('enc:CipherReference')[0].getAttribute('URI')
            encryption_list[uri] = algorithm
    return encryption_list
    
def decrypt_content(key_iv, enc, opts):
    key = key_iv[0]
    iv  = key_iv[1]
    enc = array.array('B', enc)
    plain = array.array('B')
    trunked = False
    s = len(enc) - 16
    if len(enc) - 16 > len(key) and opts['trunk'] == 0:
        print "encrypted content too long %d > %d" %(len(enc) - 16, len(key))
        return (None, None)
    elif len(enc) - 16 > len(key) and opts['trunk'] == 1:
        print "encrypted content too long %d > %d, Trunked!" %(len(enc) - 16, len(key))
        s = len(key)
        trunked = True
    if iv.tostring() != enc[0:16].tostring() :
        print "iv mismatch!"
        return (None, None)
    for i in range(s) :
        plain.append(enc[i + 16] ^ key[i])
    return (plain.tostring(), trunked)                        

def is_text_file(filename):
    return filename.lower().endswith('.html') \
    or filename.lower().endswith('.txt') \
    or filename.lower().endswith('.css') \
    or filename.lower().endswith('.xhtml')

def is_image_file(filename):
    return filename.lower().endswith('.jpg') \
    or filename.lower().endswith('.jpeg') \
    or filename.lower().endswith('.png') \
    or filename.lower().endswith('.bmp')

def analyse_epub(opts):
    """
    analyse epub file
    """
    if opts['encrypted-file'] == '' or  opts['plain-file'] == '':
        print "need encrypted file and it's plain content to analyse epub"
        sys.exit(1)
    key = gen_key(opts, opts['encrypted-file'], opts['plain-file'])
    enc_list = read_encryption_xml(opts)
    entries = list_epub_entries(opts)
    if key == None or enc_list == None or entries == None:
        sys.exit(1)
    # check algorithm should be all 'http://www.w3.org/2001/04/xmlenc#aes128-ctr'
    # search target file
    max_size = 0
    target_image = ''
    for i in enc_list.keys() :
        if enc_list[i] != 'http://www.w3.org/2001/04/xmlenc#aes128-ctr' :
            print "unknown algorithm %s of %s" % (nc_list[i], i)
            sys.exit(1)
    for i in entries :
        if i.file_size > max_size and enc_list.has_key(i.filename) :
            max_size = i.file_size
            target_image = i.filename
    target_image = target_image.encode('utf-8')
    # target_image must be an image file, and is big enough!
    if target_image != '' and max_size > 0 and is_image_file(target_image) :
        print "found target image %s, size is %d" % (target_image, max_size)
    else :
        print "target file not found!"
    # find which encrypted text content has target file
    target_image = target_image.split('/')[-1:][0]
    target_text = ''
    trunked = False
    for i in enc_list.keys() :
        if is_text_file(i.encode('utf-8')) :
            enc_txt = read_epub_file(opts, i.encode('utf-8'))
            (plain_text, trunked) = decrypt_content(key, enc_txt, opts)
            if plain_text == None:
                print "decrypt fail : %s" % (i)
                continue
            if plain_text.find(target_image) != -1:
                target_text = i.encode('utf-8')
                print "%s has %s" % (target_text, target_image)
                if(opts['verbose']) :
                    print "content is \n%s" % (plain_text)
                else :
                    print "use -v to show content"
                break
    sys.exit(0)

def decrypt_epub(opts) :
    """
    decrypt epub file
    """
    if opts['encrypted-file'] == '' or  opts['plain-file'] == '':
        print "need encrypted file and it's plain content to decrypt epub"
        sys.exit(1)
    key = gen_key(opts, opts['encrypted-file'], opts['plain-file'])
    enc_list = read_encryption_xml(opts)
    entries = list_epub_entries(opts)
    if key == None or enc_list == None or entries == None:
        sys.exit(1)
    with zipfile.ZipFile(opts['epub-file']+'.dedrm.epub', 'w', zipfile.ZIP_DEFLATED) as z :
        with zipfile.ZipFile(opts['epub-file']+'.bad.epub', 'w', zipfile.ZIP_DEFLATED) as z_bad :
            for ent in entries :
                if ent.filename[-1:] != '/':
                    if ent.filename == 'META-INF/encryption.xml' :
                        continue
                    content = read_epub_file(opts, ent.filename)
                    trunked = False
                    if enc_list.has_key(ent.filename) :
                        (plain, trunked)  = decrypt_content(key, content, opts)
                        if plain == None :
                            print "decrypt fail : %s" % (ent.filename)
                            z_bad.writestr(ent.filename, content)
                            continue
                        if trunked :
                            print "decrypt trunked : %s" % (ent.filename)
                        if is_text_file(ent.filename.encode('utf-8')) :
                            # strip end null
                            plain = plain.rstrip('\0')
                        if opts['verbose'] :
                            print "add decrypt : %s" % (ent.filename)
                        z.writestr(ent.filename, plain)
                    else:
                        if opts['verbose'] :
                            print "add plain : %s" % (ent.filename)
                        z.writestr(ent.filename, content)
            z_bad.close()
        z.close()
    

def main(argv) :
    cmd, opts = parse_cmd(argv)
    if cmd == 'list' :
        list_epub(opts)
    elif cmd == 'info' :
        info_epub(opts)
    elif cmd == 'rename' :
        rename_epub(opts)
    elif cmd == 'analyse' :
        analyse_epub(opts)
    else :
        decrypt_epub(opts)

main(sys.argv)
