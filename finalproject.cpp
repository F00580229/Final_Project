#include <bits/stdc++.h>
using namespace std;

static inline uint32_t rotr(uint32_t x, unsigned n){return (x>>n)|(x<<(32-n));}
static inline uint32_t Ch(uint32_t x,uint32_t y,uint32_t z){return (x&y)^(~x&z);}
static inline uint32_t Maj(uint32_t x,uint32_t y,uint32_t z){return (x&y)^(x&z)^(y&z);}
static inline uint32_t S0(uint32_t x){return rotr(x,2)^rotr(x,13)^rotr(x,22);}
static inline uint32_t S1(uint32_t x){return rotr(x,6)^rotr(x,11)^rotr(x,25);}
static inline uint32_t s0(uint32_t x){return rotr(x,7)^rotr(x,18)^(x>>3);}
static inline uint32_t s1(uint32_t x){return rotr(x,17)^rotr(x,19)^(x>>10);}

const uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

struct SHA256 {
    uint64_t len=0; vector<uint8_t> buf; uint32_t h[8];
    SHA256(){init();}
    void init(){len=0;buf.clear();
        uint32_t iv[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                         0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
        memcpy(h,iv,32);
    }
    void transform(const uint8_t* b){
        uint32_t w[64];
        for(int i=0;i<16;i++)
            w[i]=(b[i*4]<<24)|(b[i*4+1]<<16)|(b[i*4+2]<<8)|b[i*4+3];
        for(int i=16;i<64;i++)
            w[i]=s1(w[i-2])+w[i-7]+s0(w[i-15])+w[i-16];
        uint32_t a=h[0],b_=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],h_=h[7];
        for(int i=0;i<64;i++){
            uint32_t T1=h_+S1(e)+Ch(e,f,g)+K[i]+w[i];
            uint32_t T2=S0(a)+Maj(a,b_,c);
            h_=g; g=f; f=e; e=d+T1; d=c; c=b_; b_=a; a=T1+T2;
        }
        h[0]+=a;h[1]+=b_;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=h_;
    }
    void update(const uint8_t* d,size_t n){
        len+=n*8;
        size_t idx=0;
        if(!buf.empty()){
            size_t need=64-buf.size(),take=min(need,n);
            buf.insert(buf.end(),d,d+take);idx+=take;
            if(buf.size()==64){transform(buf.data());buf.clear();}
        }
        while(idx+64<=n){transform(d+idx);idx+=64;}
        if(idx<n)buf.insert(buf.end(),d+idx,d+n);
    }
    string finalize(){
        buf.push_back(0x80);
        size_t pad=((buf.size()%64)<=56)?(56-buf.size()%64):(120-buf.size()%64);
        buf.insert(buf.end(),pad,0);
        uint64_t L=len;
        for(int i=7;i>=0;i--)buf.push_back((L>>(i*8))&0xff);
        for(size_t i=0;i<buf.size();i+=64)transform(&buf[i]);
        ostringstream oss;oss<<hex<<setfill('0');
        for(int i=0;i<8;i++)
            oss<<setw(8)<<h[i];
        return oss.str();
    }
};

int main() {
    string filename = "textfile.txt"; 
    ifstream fin(filename, ios::binary);
    if(!fin){cerr << "Cannot open file: " << filename << "\n"; return 1;}
    
    SHA256 s;
    vector<uint8_t> buffer(4096);
    while(fin){
        fin.read((char*)buffer.data(), buffer.size());
        s.update(buffer.data(), fin.gcount());
    }
    
    
    cout << "SHA-256: " << s.finalize() << "\n";
}
