#!/usr/bin/env python3
import zipfile
import os,sys,getopt,re
import xml.dom.minidom
import array
import urllib.request, urllib.parse, urllib.error
import json

def usage() :
    print("""Usage:
    kankan download <-v> <book id>
        donwload: download epub file which book id is <xxx>, -v print progress
    kankan <command> [<options>] <epub file>
        list: list content of an epub file
            Options:
            -v | --verbose : verbose output
            -s | --size : sort by size
            -n | --name : sort by name
            -r | --reverse : reverse order when sort
        info: get meta information
            Options:
            -v | --verbose : verbose output
        rename: rename epub file
            Options:
            -f | --format : format string
                {title} for title, {contributor} for contributor, {publisher} for publisher, etc.
        analyse: analyse epub file
            Options:
            -k | --key-pairs : an encrypted file path in epub, and path of plain context of the encrypted file,
                              for example: "OEBPS/Images/coverpage.jpeg:coverpage.jpeg,OEBPS/Images/image1.jpeg:image2.jpeg"
            -t | --taget: an targe file to find, default OEBPS/Images/coverpage.jpeg
            -v | --verbose : show target text content
        dedrm: dedrm epub file
            Options:
            -k | --key-pairs : an encrypted file path in epub, and path of plain context of the encrypted file,
                              for example: "OEBPS/Images/coverpage.jpeg:coverpage.jpeg,OEBPS/Images/image1.jpeg:image2.jpeg"
            -v | --verbose : print progress
    """)

def parse_cmd(argv) :
    cmd_options = {
        'download': {'opts' : 'v', 'lopts' : ['verbose']},
        'list' : {'opts' : 'vsnr', 'lopts' : ['verbose', 'size', 'name', 'reverse']},
        'info' : {'opts' : 'v', 'lopts' : ['verbose']},
        'rename' : {'opts' : 'f:', 'lopts' : ['format=']},
        'analyse' : {'opts' : 'k:vt:', 'lopts' : ['key-pairs=', 'verbose', 'target=']},
        'dedrm' : {'opts' : 'k:vt', 'lopts' : ['key-pairs=', 'verbose', 'trunk']},
        }
    parsed_options = {
        'verbose' : 0,
        'size' : 1,
        'name' : 0,
        'reverse' : 0,
        'format' : '{title}.epub',
        'key-pairs': None,
        'target': '',
        'epub-file' : '',
        'trunk' : 0
    }
    if len(argv) <= 2:
        usage()
        sys.exit(1)
    if argv[1] in cmd_options :
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
                elif opt in ('-k', '--key-pairs') :
                    parsed_options['key-pairs'] = arg
                elif opt in ('-f', '--format') :
                    parsed_options['format'] = arg
                elif opt in ('-t', '--trunk') or  opt in ('-t', '--target'):
                    if argv[1] == 'dedrm':
                        parsed_options['trunk'] = 1
                    else:
                        parsed_options['target'] = arg
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

def parse_keypairs(opts):
    key_pairs = opts['key-pairs']
    key_pairs = str.split(key_pairs, ',')
    ret={}
    for p in key_pairs:
        (enc_file, plain_file) = str.split(p, ':')
        (key, iv) = gen_key(opts, enc_file, plain_file)
        if key == None or iv == None:
            opts['key-pairs'] = None
            return
        ret[iv.tobytes()] = key
        print("add key pair %s:%d from %s:%s" %(dump_array(iv), len(key), enc_file, plain_file))
    opts['key-pairs'] = ret

def read_epub_file(opts, filename) :
    ret = None
    try:
        with zipfile.ZipFile(opts['epub-file'], 'r') as zip_file :  
            ret = zip_file.read(filename)
    except zipfile.BadZipfile:
        print('%s is not a zip file' % (opts['epub-file']))
        ret = None
    except KeyError:
        print('no %s in %s' % (filename, opts['epub-file']))
        ret = None
    except IOError:
        print('error when read %s' % (opts['epub-file']))
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
        print('%s is not a zip file' % (opts['epub-file']))
        epub_entries = None
    except IOError:
        print('error when read %s' % (opts['epub-file']))
        epub_entries = None
    return epub_entries

def list_epub(opts) :
    epub_entries = list_epub_entries(opts)
    if epub_entries is None:
        sys.exit(1)
    if opts['verbose'] == 0 :
        print('size\tname')
        for info in epub_entries :
            print("%d\t%s" % (info.file_size, info.filename))
    else :
        print('org_size\tcompress_size\ttype\tdate_time\tname')
        for info in epub_entries :
            date_time = '%04d-%02d-%02d %02d:%02d:%02d' % info.date_time
            print("%d\t%d\t%s\t%s\t%s" % (info.file_size, info.compress_size, info.compress_type, date_time, info.filename))
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
        print("no content.opf found!")
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
        for key in list(epub_meta.keys()) :
            if key != 'meta' and key != 'identifier' :
                print('%s: %s' % (key, epub_meta[key]))
            elif  key == 'identifier' :
                print('identifier:')
                for i in list(epub_meta['identifier'].keys()) :
                    print('\t%s:\t%s' % (i, epub_meta['identifier'][i]))
            elif  key == 'meta' :
                print('meta:')
                for i in list(epub_meta['meta'].keys()) :
                    print('\t%s:\t%s' % (i, epub_meta['meta'][i]))
                
    else :
        print('title: %s' % (epub_meta['title']))
        print('publisher: %s' % (epub_meta['publisher']))
        print('creator: %s' % (epub_meta['creator']))
    sys.exit(0)

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
            title       = epub_meta['title'],
            creator     = epub_meta['creator'],
            publisher   = epub_meta['publisher'],
            subject     = epub_meta['subject'],
            description = epub_meta['description'],
            contributor = epub_meta['contributor'],
            date        = epub_meta['date'],
            source      = epub_meta['source'],
            language    = epub_meta['language'],
            relation    = epub_meta['relation'],
            coverage    = epub_meta['coverage'],
            rights      = epub_meta['rights'],
        )
    except KeyError:
        sys.exit(1)
    old_path = os.path.abspath(opts['epub-file'])
    dir_path, old_name = os.path.split(old_path)
    new_path = os.path.join(dir_path ,new_name)
    print("%s => %s" % (old_path, new_path))
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
        return (None, None)
    print("plain size %d" % len(plain))
    print("encrypt size %d" % len(enc))
    # check plain file size
    diff_len = len(enc) - 16 - len(plain)
    if diff_len < 0 or diff_len >= 16 :
        print("plain file size %d mismatch with encrypted one %d , should be [%d %d]" % \
            (len(plain), len(enc), len(enc) - 16 - 15, len(enc) - 16))
        return (None, None)
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
    print('key size %d' % (len(key)))
    print('iv size %d' % (len(iv)))
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
    
def dump_array(av):
    ret_str = ''
    for i in range(len(av)) :
        ret_str += format(av[i], 'x')
    return ret_str

def dedrm_content(enc, opts):
    enc = array.array('B', enc)
    plain = array.array('B')
    trunked = False
    if len(enc) < 16:
        print("encrypted content too small %d < %d" %(len(enc), 16))
        return (None, None)
    s = len(enc) - 16
    iv = enc[0:16]
    if iv.tobytes() in opts['key-pairs'] :
        key = opts['key-pairs'][iv.tobytes()]
    else:
        print("unknown iv %s!" %(dump_array(iv)))
        return (None, None)
    if len(enc) - 16 > len(key) and opts['trunk'] == 0:
        print("encrypted content too long %d > %d" %(len(enc) - 16, len(key)))
        return (None, None)
    elif len(enc) - 16 > len(key) and opts['trunk'] == 1:
        print("encrypted content too long %d > %d, Trunked!" %(len(enc) - 16, len(key)))
        s = len(key)
        trunked = True
    for i in range(s) :
        plain.append(enc[i + 16] ^ key[i])
    return (plain.tobytes(), trunked)                        

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
    enc_list = read_encryption_xml(opts)
    entries = list_epub_entries(opts)
    if enc_list == None or entries == None:
        sys.exit(1)
    # check algorithm should be all 'http://www.w3.org/2001/04/xmlenc#aes128-ctr'
    # search target file
    max_size = 0
    if opts['target']:
        target_image = opts['target']
        for i in entries :
            print('test %s' % (i.filename))
            if target_image == i.filename:
                max_size = i.file_size
    else:
        target_image = ''
        for i in list(enc_list.keys()) :
            if enc_list[i] != 'http://www.w3.org/2001/04/xmlenc#aes128-ctr' :
                print("unknown algorithm %s of %s" % (nc_list[i], i))
                sys.exit(1)
        for i in entries :
            if i.file_size > max_size and i.filename in enc_list :
                max_size = i.file_size
                target_image = i.filename
      
    # target_image must be an image file, and is big enough!
    if target_image and max_size > 0 and is_image_file(target_image) :
        print("found target image %s, size is %d" % (target_image, max_size))
    else :
        print("target file not found!")
    # find which encrypted text content has target file
    target_image = target_image.split('/')[-1:][0]
    target_text = ''
    trunked = False
    for i in list(enc_list.keys()) :
        if is_text_file(i) :
            enc_txt = read_epub_file(opts, i)
            (plain_text, trunked) = dedrm_content(enc_txt, opts)
            if plain_text == None:
                print("dedrm fail : %s" % (i))
                continue
            if plain_text.decode('utf-8').find(target_image) != -1:
                target_text = i
                print("%s has %s" % (target_text, target_image))
                if(opts['verbose']) :
                    print("content is \n%s" % (plain_text.decode('utf-8')))
                else :
                    print("use -v to show content")
                break
    sys.exit(0)

def dedrm_epub(opts) :
    """
    dedrm epub file
    """
    enc_list = read_encryption_xml(opts)
    entries = list_epub_entries(opts)
    if enc_list == None or entries == None:
        sys.exit(1)
    with zipfile.ZipFile(opts['epub-file']+'.dedrm.epub', 'w', zipfile.ZIP_DEFLATED) as z :
        with zipfile.ZipFile(opts['epub-file']+'.bad.epub', 'w', zipfile.ZIP_DEFLATED) as z_bad :
            for ent in entries :
                if ent.filename[-1:] != '/':
                    if ent.filename == 'META-INF/encryption.xml' :
                        continue
                    content = read_epub_file(opts, ent.filename)
                    trunked = False
                    if ent.filename in enc_list :
                        (plain, trunked)  = dedrm_content(content, opts)
                        if plain == None :
                            print("dedrm fail : %s" % (ent.filename))
                            z_bad.writestr(ent.filename, content)
                            continue
                        if trunked :
                            print("dedrm trunked : %s" % (ent.filename))
                        if is_text_file(ent.filename) :
                            # strip end null
                            plain = plain.rstrip(b'\0')
                        if opts['verbose'] :
                            print("add dedrm : %s" % (ent.filename))
                        z.writestr(ent.filename, plain)
                    else:
                        if opts['verbose'] :
                            print("add plain : %s" % (ent.filename))
                        z.writestr(ent.filename, content)
            z_bad.close()
        z.close()
    sys.exit(0)
    
def save_url_to_file(urlstr, outfile, opts):
    ret = True
    print("%s ==> %s" %(urlstr, outfile))
    try:
        save_size = 0
        req = urllib.request.Request(url=urlstr, method='GET')
        fp = urllib.request.urlopen(req);
        with open( outfile, 'wb') as fo :
            output_size = int(fp.getheader('content-length'))
            while True:
                output_data = fp.read(1024)
                if not output_data:
                    break;
                fo.write(output_data)
                save_size += len(output_data)
                if opts['verbose'] :
                    if output_size:
                        sys.stdout.write("Download progress: %d\r" % (save_size * 100.0 / output_size) )
                    else:
                        sys.stdout.write("Download bytes: %d\r" % (save_size) )
    except IOError:
        print("can not save %s" %(urlstr))
        ret = False
    else:
        fp.close()
    return ret

# http://www.duokan.com/store/v0/web/book/xxx
def download_epub(opts):
    info_url = 'http://www.duokan.com/store/v0/web/book/' + opts['epub-file'];
    print('url is %s' %(info_url))

    try:
        fp = urllib.request.urlopen(info_url);
        book_info = fp.read()
    except IOError:
        print("can not load %s" %(info_url))
        sys.exit(1)
    else:
        fp.close()

    try:
        book_hash = json.loads(book_info)
        book_url = book_hash['book']['epub']
        coverpage_url = book_hash['book']['cover']
    except ValueError:
        print("can not download book info, return %s" %(book_info))
        sys.exit(1)
    except KeyError:
        if opts['verbose'] == 1:
            print("book info load error, data is %s" %(book_hash))
        else:
            print("book info load error, use -v see detail")
        sys.exit(1)

    if coverpage_url[-2] == '!' and coverpage_url[-1] == 'm':
        coverpage_url = coverpage_url[0:-2]

    book_name = book_url.split()[-1].split('/')[-1]
    coverpage_name = coverpage_url.split()[-1].split('/')[-1]

    print('book_url is %s' %(book_url))
    print('coverpage_url is %s' %(coverpage_url))

    save_url_to_file(coverpage_url, coverpage_name, opts)
    save_url_to_file(book_url, book_name, opts)

    print("use './kankan.py analyse -v -k OEBPS/Images/coverpage.jpg:%s %s' to find targe image" % (coverpage_name, book_name))

    sys.exit(0)

def main(argv) :
    cmd, opts = parse_cmd(argv)
    if opts['key-pairs'] != None:
        parse_keypairs(opts)
        if opts['key-pairs'] == None:
            print("parse key pairs error!")
            sys.exit(1)
    if cmd == 'download' :
        download_epub(opts)
    elif cmd == 'list' :
        list_epub(opts)
    elif cmd == 'info' :
        info_epub(opts)
    elif cmd == 'rename' :
        rename_epub(opts)
    elif cmd == 'analyse' :
        analyse_epub(opts)
    elif cmd == 'dedrm' :
        dedrm_epub(opts)
    else:
        sys.exit(1)

main(sys.argv)
