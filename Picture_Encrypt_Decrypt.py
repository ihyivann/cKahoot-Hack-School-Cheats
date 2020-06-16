import numpy as np
import matplotlib.pyplot as plt
import cv2
import pywt
import os
#import pywt.data
import hashlib
from pathlib import Path
from matplotlib import pyplot as plt
import PIL.Image as IMG
from tkinter.filedialog import  askdirectory
from tkinter.filedialog import askopenfilename
from tkinter.filedialog import asksaveasfilename
import pywt.data
import tkinter as tk
from tkinter import *
from tkinter.messagebox import *
import tensorflow as tf
import binascii
import py2exe
import six
import packaging
import packaging.version
import packaging.specifiers
import packaging.requirements


def sha256fun(key):
    m2 = hashlib.sha256()
    m2.update(key.encode('utf-8'))
    cryptstr=m2.hexdigest()
    return cryptstr

def initS(KeyBytes):
    keyLen = len(KeyBytes)
    S = list(range(256))
    j = 0
    j = 0
    for i in range(256):
        j = (j + S[i] + KeyBytes[i % keyLen]) % 256
        S[i], S[j] = S[j], S[i]
    return S
def rc4_crypt(PlainBytes: bytes, KeyBytes: bytes) -> str:
    '''[summary]
    rc4 crypt
    Arguments:
        PlainBytes {[bytes]} -- [plain bytes]
        KeyBytes {[bytes]} -- [key bytes]

    Returns:
        [string] -- [hex string]
    '''

    keystreamList = []
    cipherList = []
    keyLen = len(KeyBytes)
    plainLen = len(PlainBytes)
    S = initS(KeyBytes)
    i = 0
    j = 0
    for m in range(plainLen):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        cipherList.append(k ^ PlainBytes[m])

    result_hexstr = ''.join(['%02x' % i for i in cipherList])
    return result_hexstr.upper()

def rc4_decrypt(CipherBytes: bytes, KeyBytes:bytes) -> str:
    '''[summary]
    rc4 crypt
    Arguments:
        PlainBytes {[bytes]} -- [plain bytes]
        KeyBytes {[bytes]} -- [key bytes]

    Returns:
        [string] -- [hex string]
    '''

    keystreamList = []
    S=initS(KeyBytes)
    plainList = []
    cipherLen = len(CipherBytes)
    i = 0
    j = 0
    for m in range(cipherLen):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        plainList.append(k ^ CipherBytes[m])

    result_hexstr = ''.join(['%02x' % i for i in plainList])
    return result_hexstr.upper()

def str_to_hex(s):
    return ''.join([hex(ord(c)).replace('0x', '') for c in s])

def hex_to_str(s):
    return ''.join([chr(i) for i in [int(b, 16) for b in s.split(' ')]])

def str_to_bin(s):
    return ''.join([bin(ord(c)).replace('0b', '') for c in s])

def bin_to_str(s):
    return ''.join([chr(i) for i in [int(b, 2) for b in s.split(' ')]])

def str2BITS(s):
    if len(s)<2:
        t=2-len(s)
        for count in range (0,t):
            s='0'+s
    else:
        pass
    return s

def Hex2Dec(c):
    if c=='0':
        return 0
    elif c=='1':
        return 1
    elif c=='2':
        return 2
    elif c=='3':
        return 3
    elif c=='4':
        return 4
    elif c=='5':
        return 5
    elif c=='6':
        return 6
    elif c=='7':
        return 7
    elif c=='8':
        return 8
    elif c=='9':
        return 9
    elif c=='A':
        return 10
    elif c=='B':
        return 11
    elif c=='C':
        return 12
    elif c=='D':
        return 13
    elif c=='E':
        return 14
    elif c=='F':
        return 15

def cryptojpg(img,key):
    '''
    按照给定的序列,对图片进行像素级加密
    :return:
    '''
    imgstr=''
    for i in range(len(img)):
        for j in range(len(img[0])):
            s=''
            s=(hex(int(img[i][j])))[2:]
            s=str2BITS(s)
            imgstr=imgstr+s.upper()
    key=sha256fun(key)
    #tmp=rc4_crypt(binascii.a2b_hex(imgstr),binascii.a2b_hex(str_to_hex((key).upper())))
    tmp=rc4_crypt(binascii.a2b_hex(imgstr),binascii.a2b_hex((key).upper()))
    count=0
    for i in range(len(img)):
        for j in range(len(img[0])):
            t=tmp[count:count+2]
            count+=2
            k=Hex2Dec(t[0])*16+Hex2Dec(t[1])
            img[i][j]=k%256
    return img

def decryptojpg(img,key):
    '''
    按照给定的序列,对图片进行像素级加密
    :return:
    '''
    imgstr=''
    for i in range(len(img)):
        for j in range(len(img[0])):
            s=''
            s=(hex(int(img[i][j])))[2:]
            s=str2BITS(s)
            imgstr=imgstr+s.upper()
    key=sha256fun(key)
    #tmp=rc4_decrypt(binascii.a2b_hex(imgstr),binascii.a2b_hex(str_to_hex((key).upper())))
    tmp=rc4_decrypt(binascii.a2b_hex(imgstr),binascii.a2b_hex((key).upper()))
    count=0
    for i in range(len(img)):
        for j in range(len(img[0])):
            t=tmp[count:count+2]
            count+=2
            k=Hex2Dec(t[0])*16+Hex2Dec(t[1])
            img[i][j]=k%256
    return img

def DecryptJpg(key,file_name,dest):
    #key="qweqweqw"
    image_raw_data = tf.io.gfile.GFile(file_name, 'rb').read()
    with tf.compat.v1.Session() as sess:
        img_data = tf.image.decode_jpeg(image_raw_data)
        img_data_value=img_data.eval()
        #print(img_data_value)
        img_data_value=np.ndarray.astype(img_data_value,dtype=np.float32)
        (B,G,R)=cv2.split(img_data_value)
        #print("------B------")
        #print(B)
        #print("------G------")
        #print(G)
        #print("------R------")
        #print(R)
        bgr_b=decryptojpg(B,key)
        bgr_g=decryptojpg(G,key)
        bgr_r=decryptojpg(R,key)
        save_img(bgr_r,bgr_g,bgr_b,file_name,dest)
    tk.messagebox.showinfo("提示信息","解密完成")

def save_img(bgr_b,bgr_g,bgr_r,file_name,dest):
    """
    合并图片的三个通道,存储图片
    :return:
    """

    img = cv2.merge([bgr_b, bgr_g, bgr_r])
    #演示时，此处需修改为文件名，默认覆盖原文件
    #self.img_name=self.img_name+"jpg2bmp.bmp"
    #cv2.imwrite(self.img_name, img)
    cv2.imwrite(dest, img)
    #print(img_name + "  Done")

def EncryptJpg(key,file_name,dest):
    #key="qweqweqw"
    image_raw_data = tf.io.gfile.GFile(file_name, 'rb').read()
    with tf.compat.v1.Session() as sess:
        img_data = tf.image.decode_jpeg(image_raw_data)
        img_data_value=img_data.eval()
        #print(img_data_value)
        img_data_value=np.ndarray.astype(img_data_value,dtype=np.float32)
        (B,G,R)=cv2.split(img_data_value)
        #print("------B------")
        #print(B)
        #print("------G------")
        #print(G)
        #print("------R------")
        #print(R)
        bgr_b=cryptojpg(B,key)
        bgr_g=cryptojpg(G,key)
        bgr_r=cryptojpg(R,key)
        save_img(bgr_r,bgr_g,bgr_b,file_name,dest)
    tk.messagebox.showinfo("提示信息","加密完成")


class Iter_bmps(object):

    def __init__(self, file_name, key, mode,dest):
        """

        :param path_name: 文件夹路径
        :param key: 密钥
        :param mode: 模式:加密/解密
        """
        #crypto_list = Cryptokey(key)
        #self.crypto_list = crypto_list.get_crypto_list()  # 获取密钥序列
        self.key=key
        self.file_name = file_name
        self.mode = mode
        self.dest=dest
        self.iterallbmp()

    def iterallbmp(self):
        """
        遍历给定的目录,获取bmp格式图片的相对路径,并进行加密
        :return:
        """
        BmpBGR(str(self.file_name), self.key, self.mode, str(self.dest))
        '''
        for item in Path(self.path_name).rglob('*.bmp'):
            BmpBGR(str(item), self.key, self.mode)
        '''

class BmpBGR(object):

    def __init__(self, img_name, key, mode, dest):
        """

        :param img_name:图片名称
        :param crypto_list: 加密列表
        :param mode: 模式:加密/解密
        """
        self.mode = mode
        self.img_name = img_name
        self.key = key
        self.dest = dest
        self.B = None
        self.G = None
        self.R = None
        self.bgr_b = None
        self.bgr_g = None
        self.bgr_r = None
        self.load_img()
        self.trans_bgr()
        #self.show_img()
        self.save_img()

    def load_img(self):
        """
        分离图片的三个通道
        :return:
        """
        img = cv2.imread(self.img_name, 1)

        # 将多通道图像变为单通道图像
        (self.B, self.G, self.R) = cv2.split(img)
        self.B = self.B.astype(np.float32)
        self.G = self.G.astype(np.float32)
        self.R = self.R.astype(np.float32)

    def trans_bgr(self):
        """
        依次对图像的BGR三个通道进行小波变换,并进行低频系数加密/解密,然后小波逆变换
        返回加密/解密后的图像
        :return:
        """
        bb = Bmpwave(self.img_name, self.B, self.key, self.mode)
        self.bgr_b = bb.get_img()

        gg = Bmpwave(self.img_name, self.G, self.key, self.mode)
        self.bgr_g = gg.get_img()

        rr = Bmpwave(self.img_name, self.R, self.key, self.mode)
        self.bgr_r = rr.get_img()


    def save_img(self):
        """
        合并图片的三个通道,存储图片
        :return:
        """

        img = cv2.merge([self.bgr_b, self.bgr_g, self.bgr_r])
        #演示时，此处需修改为文件名，默认覆盖原文件
        #self.img_name=self.img_name+"jpg2bmp.bmp"
        #cv2.imwrite(self.img_name, img)
        cv2.imwrite(self.dest, img)
        tk.messagebox.showinfo("提示信息","处理完成")
        #print(self.img_name + "  Done")

class Bmpwave(object):

    def __init__(self, img_name, img, key, mode):
        self.img_name = img_name
        self.mode = mode
        self.trans_list = None
        self.img = img
        self.key = key
        self.LL = None
        self.LH = None
        self.HL = None
        self.HH = None
        self.trans_bmp()
        self.wavelet_trans()
        self.wavelet_itrans()


    def wavelet_trans(self):
        """
        对图像的某一通道进行haar小波变换
        :return:
        """
        self.LL, (self.LH, self.HL, self.HH) = pywt.dwt2(self.img, 'haar')

    def wavelet_itrans(self):
        """
        对图像的某一通道进行haar小波逆变换
        :return:
        """
        self.img = pywt.idwt2((self.LL, (self.LH, self.HL, self.HH)), 'haar')

    def trans_bmp(self):
        if self.mode == 'e':
            self.cryptobmp()
        elif self.mode == 'd':
            self.decryptobmp()
        else:
            exit(1)

    def cryptobmp(self):
        '''
        按照给定的序列,对图片进行像素级加密
        :return:
        '''
        imgstr=''
        for i in range(len(self.img)):
            for j in range(len(self.img[0])):
                s=''
                s=(hex(int(self.img[i][j])))[2:]
                s=str2BITS(s)
                imgstr=imgstr+s.upper()
        self.key=sha256fun(self.key)       		
        #tmp=rc4_crypt(binascii.a2b_hex(imgstr),binascii.a2b_hex(str_to_hex((self.key).upper())))
        tmp = rc4_crypt(binascii.a2b_hex(imgstr), binascii.a2b_hex((self.key).upper()))
        count=0
        for i in range(len(self.img)):
            for j in range(len(self.img[0])):
                t=tmp[count:count+2]
                count+=2
                k=Hex2Dec(t[0])*16+Hex2Dec(t[1])
                self.img[i][j]=k
        #self.img[i][j]=float(t%256)
                #salt = (self.crypto_list[i % 64] * self.crypto_list[j % 64]) % 256
                #self.img[i][j] = (self.img[i][j] + salt) % 256


    def decryptobmp(self):
        imgstr=''
        for i in range(len(self.img)):
            for j in range(len(self.img[0])):
                s=''
                s=(hex(int(self.img[i][j])))[2:]
                s=str2BITS(s)
                imgstr=imgstr+s.upper()
        self.key=sha256fun(self.key)
        #tmp = rc4_decrypt(binascii.a2b_hex(imgstr), binascii.a2b_hex(str_to_hex((self.key).upper())))
        tmp = rc4_decrypt(binascii.a2b_hex(imgstr), binascii.a2b_hex((self.key).upper()))
        count=0
        for i in range(len(self.img)):
            for j in range(len(self.img[0])):
                t=tmp[count:count+2]
                count+=2
                k=Hex2Dec(t[0])*16+Hex2Dec(t[1])
                self.img[i][j]=k

        '''
        for i in range(len(self.img)):
            for j in range(len(self.img[0])):
                salt = (self.crypto_list[i % 64] * self.crypto_list[j % 64]) % 256
                self.img[i][j] = (self.img[i][j] - salt) % 256
        '''

    def get_img(self):
        """
        获取img
        :return: 图像对象
        """
        return self.img

class Cryptokey(object):
    def __init__(self, key):
        self.key = key
        self.crypto_list = None
        self.sha256fun()

    def sha256fun(self):
        m2 = hashlib.sha256()
        m2.update(self.key.encode('utf-8'))
        self.crypto_list = [int(ord(x)) for x in m2.hexdigest()]

    def get_crypto_list(self):
        return self.crypto_list


# 目录下所有的bmp转换为jpg
class BmpToJpg(object):
    def __init__(self,master=None):
        self.root=master
        self.root.title("bmp批量转为JPG服务")
        self.root.geometry("400x100")
        self.src=StringVar()
        self.createPage()
        self.path=StringVar()

    def createPage(self):
        self.page=Frame(self.root)
        self.page.pack()
        Label(self.page, text='源文件夹: ').grid(row=1, stick=W, pady=10)
        Entry(self.page, textvariable=self.src).grid(row=1, column=1, stick=E)
        Button(self.page, text='选择路径', command=self.selectPath).grid(row=1, column=2,stick=W, pady=10)
        Button(self.page, text='转换', command=self.BMP2JPG).grid(row=3, stick=W, pady=10)
        Button(self.page, text='返回', command=self.Return).grid(row=3, column=1, stick=E)

    def selectPath(self):
        path_=askdirectory()
        self.src.set(path_)

    def Return(self):
        self.page.destroy()
        init(root)

    def BMP2JPG(self):
        source=str(self.src.get())
        source.replace('\\','\\\\')
        count = 0
        for fileName in os.listdir(source):
            fileNameList = os.path.splitext(fileName)
            if fileNameList[1] == '.bmp':
                count = count + 1
                newFileName = fileNameList[0] + ".jpg"
                #print(newFileName)
                im = IMG.open(source + "\\" + fileName)
                im.save(source + "\\" + newFileName)
            else:
                pass
        tk.messagebox.showinfo("提示信息", str(count)+"张BMP图片转化为JPG格式完成！")

class BmpEncrypt():
    def __init__(self,master=None):
        self.root=master
        self.root.title("bmp加密服务")
        self.root.geometry("400x240")
        self.src=StringVar()
        self.dest = StringVar()
        self.key=StringVar()
        self.createPage()

    def createPage(self):
        self.page=Frame(self.root)
        self.page.pack()
        Label(self.page, text='源文件: ').grid(row=1, stick=W, pady=10)
        Entry(self.page, textvariable=self.src).grid(row=1, column=1, stick=E)
        Button(self.page, text='浏览', command=self.selectSrcFile).grid(row=1, column=2, stick=W, pady=10)
        Label(self.page, text='目标文件: ').grid(row=2, stick=W, pady=10)
        Entry(self.page, textvariable=self.dest).grid(row=2, column=1, stick=E)
        Button(self.page, text='浏览', command=self.selectDestFile).grid(row=2, column=2, stick=W, pady=10)
        Label(self.page, text='密钥: ').grid(row=3, stick=W, pady=10)
        Entry(self.page, textvariable=self.key).grid(row=3, column=1, stick=E)
        Button(self.page, text='加密', command=self.encrypt).grid(row=4, stick=W, pady=10)
        Button(self.page, text='返回', command=self.Return).grid(row=4, column=1, stick=E)
    def selectDestFile(self):
        file_=asksaveasfilename()
        file_list=os.path.splitext(file_)
        if file_list[len(file_list)-1]!=".bmp":
            tk.messagebox.showwarning("警示信息", "请在您待保存的文件名后加入后缀.bmp!")
            self.Return()
        else:
            self.dest.set(file_)

    def selectSrcFile(self):
        file_=askopenfilename()
        file_list=os.path.splitext(file_)
        if file_list[1]!='.bmp':
            tk.messagebox.showwarning("警示信息","您选择的文件不符合加密类型!")
            self.Return()
        else:
            self.src.set(file_)


    def encrypt(self):
        key=str(self.key.get())
        mode='e'
        src=str(self.src.get())
        dest=str(self.dest.get())
        Iter_bmps(src,key,mode,dest)

    def Return(self):
        self.page.destroy()
        init(root)

class BmpDecrypt():
    def __init__(self,master=None):
        self.root=master
        self.root.title("bmp解密服务")
        self.root.geometry("400x240")
        self.src=StringVar()
        self.dest = StringVar()
        self.key=StringVar()
        self.createPage()

    def createPage(self):
        self.page=Frame(self.root)
        self.page.pack()
        Label(self.page, text='源文件: ').grid(row=1, stick=W, pady=10)
        Entry(self.page, textvariable=self.src).grid(row=1, column=1, stick=E)
        Button(self.page, text='浏览', command=self.selectSrcFile).grid(row=1, column=2, stick=W, pady=10)
        Label(self.page, text='目标文件: ').grid(row=2, stick=W, pady=10)
        Entry(self.page, textvariable=self.dest).grid(row=2, column=1, stick=E)
        Button(self.page, text='浏览', command=self.selectDestFile).grid(row=2, column=2, stick=W, pady=10)
        Label(self.page, text='密钥: ').grid(row=3, stick=W, pady=10)
        Entry(self.page, textvariable=self.key).grid(row=3, column=1, stick=E)
        Button(self.page, text='解密', command=self.encrypt).grid(row=4, stick=W, pady=10)
        Button(self.page, text='返回', command=self.Return).grid(row=4, column=1, stick=E)
    def selectDestFile(self):
        file_=asksaveasfilename()
        file_list=os.path.splitext(file_)
        if file_list[len(file_list)-1]!=".bmp":
            tk.messagebox.showwarning("警示信息", "请在您待保存的文件名后加入后缀.bmp!")
            self.Return()
        else:
            self.dest.set(file_)

    def selectSrcFile(self):
        file_=askopenfilename()
        file_list=os.path.splitext(file_)
        if file_list[1]!='.bmp':
            tk.messagebox.showwarning("警示信息","您选择的文件不符合加密类型!")
            self.Return()
        else:
            self.src.set(file_)

    def encrypt(self):
        key=str(self.key.get())
        mode='d'
        src=str(self.src.get())
        dest=str(self.dest.get())
        Iter_bmps(src,key,mode,dest)

    def Return(self):
        self.page.destroy()
        init(root)

class JpgEncrypt():
    def __init__(self, master=None):
        self.root = master
        self.root.title("JPG加密服务")
        self.root.geometry("400x240")
        self.src = StringVar()
        self.dest = StringVar()
        self.key = StringVar()
        self.createPage()

    def createPage(self):
        self.page = Frame(self.root)
        self.page.pack()
        Label(self.page, text='源文件: ').grid(row=1, stick=W, pady=10)
        Entry(self.page, textvariable=self.src).grid(row=1, column=1, stick=E)
        Button(self.page, text='浏览', command=self.selectSrcFile).grid(row=1, column=2, stick=W, pady=10)
        Label(self.page, text='目标文件: ').grid(row=2, stick=W, pady=10)
        Entry(self.page, textvariable=self.dest).grid(row=2, column=1, stick=E)
        Button(self.page, text='浏览', command=self.selectDestFile).grid(row=2, column=2, stick=W, pady=10)
        Label(self.page, text='密钥: ').grid(row=3, stick=W, pady=10)
        Entry(self.page, textvariable=self.key).grid(row=3, column=1, stick=E)
        Button(self.page, text='加密', command=self.encrypt).grid(row=4, stick=W, pady=10)
        Button(self.page, text='返回', command=self.Return).grid(row=4, column=1, stick=E)

    def selectDestFile(self):
        file_ = asksaveasfilename()
        file_list=os.path.splitext(file_)
        if file_list[len(file_list)-1]!=".jpg" and file_list[len(file_list)-1]!=".jpeg":
            tk.messagebox.showinfo("警示信息","请在您待保存的文件名后加入后缀.jpg或.jpeg!")
            self.Return()
        else:
            self.dest.set(file_)

    def selectSrcFile(self):
        file_ = askopenfilename()
        file_list=os.path.splitext(file_)
        if file_list[1]!=".jpg" and file_list[1]!=".jpeg":
            tk.messagebox.showinfo("警示信息", "您选择的文件不符合加密类型!")
            self.Return()
        else:
            self.src.set(file_)

    def encrypt(self):
        key = str(self.key.get())
        mode = 'e'
        src = str(self.src.get())
        dest = str(self.dest.get())
        EncryptJpg(key,src,dest)

    def Return(self):
        self.page.destroy()
        init(root)

class JpgDecrypt():
    def __init__(self, master=None):
        self.root = master
        self.root.title("JPG解密服务")
        self.root.geometry("400x240")
        self.src = StringVar()
        self.dest = StringVar()
        self.key = StringVar()
        self.createPage()

    def createPage(self):
        self.page = Frame(self.root)
        self.page.pack()
        Label(self.page, text='源文件: ').grid(row=1, stick=W, pady=10)
        Entry(self.page, textvariable=self.src).grid(row=1, column=1, stick=E)
        Button(self.page, text='浏览', command=self.selectSrcFile).grid(row=1, column=2, stick=W, pady=10)
        Label(self.page, text='目标文件: ').grid(row=2, stick=W, pady=10)
        Entry(self.page, textvariable=self.dest).grid(row=2, column=1, stick=E)
        Button(self.page, text='浏览', command=self.selectDestFile).grid(row=2, column=2, stick=W, pady=10)
        Label(self.page, text='密钥: ').grid(row=3, stick=W, pady=10)
        Entry(self.page, textvariable=self.key).grid(row=3, column=1, stick=E)
        Button(self.page, text='解密', command=self.decrypt).grid(row=4, stick=W, pady=10)
        Button(self.page, text='返回', command=self.Return).grid(row=4, column=1, stick=E)

    def selectDestFile(self):
        file_ = asksaveasfilename()
        file_list=os.path.splitext(file_)
        if file_list[len(file_list)-1]!=".jpg" and file_list[len(file_list)-1]!=".jpeg":
            tk.messagebox.showwarning("警示信息","请在您待保存的文件名后加入后缀.jpg或.jpeg!")
            self.Return()
        else:
            self.dest.set(file_)

    def selectSrcFile(self):
        file_ = askopenfilename()
        file_list=os.path.splitext(file_)
        if file_list[1]!=".jpg" and file_list[1]!=".jpeg":
            tk.messagebox.showwarning("警示信息","您选择的文件不符合加密类型!")
            self.Return()
        else:
            self.src.set(file_)

    def decrypt(self):
        key = str(self.key.get())
        #mode = 'd'
        src = str(self.src.get())
        dest = str(self.dest.get())
        DecryptJpg(key,src,dest)

    def Return(self):
        self.page.destroy()
        init(root)

class init(object):
    def __init__(self, master=None):
        self.root = master  # 定义内部变量root
        self.root.title("图像加解密")
        self.root.geometry("500x450")  # 设置窗口大小
        self.createPage()

    def createPage(self):
        self.page = Frame(self.root)  # 创建Frame
        self.page.pack()
        Label(self.page).grid(row=0, stick=W)
        Button(self.page, text='BMP转JPG', command=self.bmp2jpg, width=8, height=2).grid(row=3, stick=W, pady=10)
        Button(self.page, text='BMP加密', command=self.bmpencrypt, width=8, height=2).grid(row=4, stick=W, pady=10)
        Button(self.page, text='BMP解密', command=self.bmpdecrypt, width=8, height=2).grid(row=5, stick=W, pady=10)
        Button(self.page, text='JPG加密', command=self.jpgencrypt, width=8, height=2).grid(row=6, stick=W, pady=10)
        Button(self.page, text='JPG解密', command=self.jpgdecrypt, width=8, height=2).grid(row=7, stick=W, pady=10)
        Button(self.page, text='退出', command=self.page.quit, width=8, height=2).grid(row=8, stick=W, pady=10)

    def bmp2jpg(self):
        self.page.destroy()
        BmpToJpg(root)

    def bmpencrypt(self):
        self.page.destroy()
        BmpEncrypt(root)

    def bmpdecrypt(self):
        self.page.destroy()
        BmpDecrypt(root)

    def jpgencrypt(self):
        self.page.destroy()
        JpgEncrypt(root)

    def jpgdecrypt(self):
        self.page.destroy()
        JpgDecrypt(root)



if __name__ == '__main__':
    root = tk.Tk()
    root.title("图片加解密")
    a = init(root)
    root.mainloop()

