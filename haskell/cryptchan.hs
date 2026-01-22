{-
NullSec CryptChan - Encrypted Covert Channels
Language: Haskell
Author: bad-antics
License: NullSec Proprietary

Encrypted covert communication channels using various protocols.
-}

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent
import Control.Exception
import Control.Monad
import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Error
import Crypto.Hash
import Crypto.KDF.PBKDF2
import Crypto.Random
import Data.Bits
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as C8
import Data.Char
import Data.List
import Data.Word
import Network.DNS
import Network.Socket hiding (send, recv)
import Network.Socket.ByteString
import System.Console.GetOpt
import System.Environment
import System.Exit
import System.IO
import Text.Printf

-- Version
version :: String
version = "1.0.0"

-- Banner
banner :: String
banner = unlines
    [ ""
    , "    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  "
    , "    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  "
    , "   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ "
    , "   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒"
    , "   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░"
    , "   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄"
    , "   █░░░░░░░░░░░░ C R Y P T C H A N ░░░░░░░░░░░░░░░░░░░░░░░░░░░░█"
    , "   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀"
    , "                      bad-antics v" ++ version
    , ""
    ]

-- Configuration
data Config = Config
    { cfgMode       :: Mode
    , cfgChannel    :: Channel
    , cfgHost       :: String
    , cfgPort       :: Int
    , cfgKey        :: String
    , cfgDomain     :: String
    , cfgVerbose    :: Bool
    } deriving (Show)

data Mode = Server | Client | Help
    deriving (Show, Eq)

data Channel = DNSTunnel | ICMPChannel | HTTPCovert | TimingChannel
    deriving (Show, Eq, Read)

defaultConfig :: Config
defaultConfig = Config
    { cfgMode = Help
    , cfgChannel = DNSTunnel
    , cfgHost = "127.0.0.1"
    , cfgPort = 53
    , cfgKey = ""
    , cfgDomain = "covert.local"
    , cfgVerbose = False
    }

-- Command line options
options :: [OptDescr (Config -> Config)]
options =
    [ Option ['m'] ["mode"]
        (ReqArg (\s c -> c { cfgMode = parseMode s }) "MODE")
        "Mode: server/client"
    , Option ['c'] ["channel"]
        (ReqArg (\s c -> c { cfgChannel = read s }) "CHANNEL")
        "Channel: DNSTunnel/ICMPChannel/HTTPCovert/TimingChannel"
    , Option ['h'] ["host"]
        (ReqArg (\s c -> c { cfgHost = s }) "HOST")
        "Target host"
    , Option ['p'] ["port"]
        (ReqArg (\s c -> c { cfgPort = read s }) "PORT")
        "Port number"
    , Option ['k'] ["key"]
        (ReqArg (\s c -> c { cfgKey = s }) "KEY")
        "Encryption key"
    , Option ['d'] ["domain"]
        (ReqArg (\s c -> c { cfgDomain = s }) "DOMAIN")
        "Domain for DNS tunneling"
    , Option ['v'] ["verbose"]
        (NoArg (\c -> c { cfgVerbose = True }))
        "Verbose output"
    , Option ['?'] ["help"]
        (NoArg (\c -> c { cfgMode = Help }))
        "Show help"
    ]

parseMode :: String -> Mode
parseMode "server" = Server
parseMode "client" = Client
parseMode _        = Help

-- Crypto utilities
deriveKey :: ByteString -> ByteString
deriveKey password = 
    let params = Parameters { iterCounts = 100000, outputLength = 32 }
        salt = "nullsec_cryptchan_v1" :: ByteString
    in fastPBKDF2_SHA256 params password salt

encrypt :: ByteString -> ByteString -> IO ByteString
encrypt key plaintext = do
    iv <- getRandomBytes 16
    let cipher = throwCryptoError $ cipherInit key :: AES256
        encrypted = cbcEncrypt cipher (throwCryptoError $ makeIV iv) (padPKCS7 plaintext)
    return $ BS.append iv encrypted

decrypt :: ByteString -> ByteString -> Either String ByteString
decrypt key ciphertext = 
    if BS.length ciphertext < 32
    then Left "Ciphertext too short"
    else
        let (iv, encrypted) = BS.splitAt 16 ciphertext
            cipher = throwCryptoError $ cipherInit key :: AES256
        in case makeIV iv of
            CryptoFailed e -> Left $ show e
            CryptoPassed ivVal -> 
                case unpadPKCS7 $ cbcDecrypt cipher ivVal encrypted of
                    Nothing -> Left "Invalid padding"
                    Just pt -> Right pt

-- PKCS7 padding
padPKCS7 :: ByteString -> ByteString
padPKCS7 bs = 
    let blockSize = 16
        padLen = blockSize - (BS.length bs `mod` blockSize)
        padding = BS.replicate padLen (fromIntegral padLen)
    in BS.append bs padding

unpadPKCS7 :: ByteString -> Maybe ByteString
unpadPKCS7 bs
    | BS.null bs = Nothing
    | otherwise = 
        let padLen = fromIntegral $ BS.last bs
        in if padLen > 0 && padLen <= 16 && 
              all (== BS.last bs) (BS.unpack $ BS.drop (BS.length bs - padLen) bs)
           then Just $ BS.take (BS.length bs - padLen) bs
           else Nothing

-- DNS Tunneling
dnsEncode :: ByteString -> String -> [String]
dnsEncode payload domain = 
    let encoded = C8.unpack $ B64.encode payload
        -- Split into 63-char labels (DNS limit)
        labels = chunksOf 63 $ filter (/= '=') encoded
        -- Create subdomains
    in [intercalate "." (l : [domain]) | l <- labels]

dnsDecode :: [String] -> String -> Either String ByteString
dnsDecode queries domain = 
    let -- Extract encoded data from queries
        extractLabel q = takeWhile (/= '.') q
        encoded = concatMap extractLabel queries
        -- Add padding back
        padded = encoded ++ replicate ((4 - length encoded `mod` 4) `mod` 4) '='
    in case B64.decode (C8.pack padded) of
        Left e -> Left e
        Right bs -> Right bs

chunksOf :: Int -> [a] -> [[a]]
chunksOf _ [] = []
chunksOf n xs = take n xs : chunksOf n (drop n xs)

-- DNS Server
runDNSServer :: Config -> IO ()
runDNSServer Config{..} = do
    let key = deriveKey (C8.pack cfgKey)
    
    putStrLn $ "[*] Starting DNS covert channel server on port " ++ show cfgPort
    putStrLn $ "[*] Domain: " ++ cfgDomain
    
    sock <- socket AF_INET Datagram defaultProtocol
    bind sock (SockAddrInet (fromIntegral cfgPort) 0)
    
    putStrLn "[*] Waiting for covert messages..."
    
    forever $ do
        (msg, addr) <- recvFrom sock 512
        
        when cfgVerbose $ do
            putStrLn $ "[<] Received query from " ++ show addr
        
        -- Parse DNS query (simplified)
        case parseDNSQuery msg of
            Nothing -> when cfgVerbose $ putStrLn "[!] Invalid DNS query"
            Just query -> do
                when cfgVerbose $ putStrLn $ "[*] Query: " ++ query
                
                -- Extract and decode payload
                case dnsDecode [query] cfgDomain of
                    Left e -> when cfgVerbose $ putStrLn $ "[!] Decode error: " ++ e
                    Right encPayload -> 
                        case decrypt key encPayload of
                            Left e -> when cfgVerbose $ putStrLn $ "[!] Decrypt error: " ++ e
                            Right payload -> do
                                putStrLn $ "[+] Message: " ++ C8.unpack payload
                                
                                -- Send DNS response
                                let response = buildDNSResponse msg "OK"
                                sendTo sock response addr
                                return ()

-- DNS Client
runDNSClient :: Config -> IO ()
runDNSClient Config{..} = do
    let key = deriveKey (C8.pack cfgKey)
    
    putStrLn $ "[*] DNS covert channel client"
    putStrLn $ "[*] Server: " ++ cfgHost ++ ":" ++ show cfgPort
    putStrLn $ "[*] Domain: " ++ cfgDomain
    putStrLn "[*] Enter messages to send (Ctrl-D to quit):"
    
    sock <- socket AF_INET Datagram defaultProtocol
    addr <- resolve cfgHost cfgPort
    
    forever $ do
        putStr "> "
        hFlush stdout
        line <- getLine
        
        unless (null line) $ do
            -- Encrypt message
            encPayload <- encrypt key (C8.pack line)
            
            -- Encode as DNS queries
            let queries = dnsEncode encPayload cfgDomain
            
            forM_ queries $ \query -> do
                when cfgVerbose $ putStrLn $ "[>] Sending: " ++ query
                
                let dnsQuery = buildDNSQuery query
                sendTo sock dnsQuery addr
                
                -- Wait for response
                (response, _) <- recvFrom sock 512
                when cfgVerbose $ putStrLn "[<] Response received"
            
            putStrLn "[+] Message sent"

-- Simplified DNS parsing (real implementation would use dns library)
parseDNSQuery :: ByteString -> Maybe String
parseDNSQuery bs
    | BS.length bs < 12 = Nothing
    | otherwise = 
        let -- Skip header (12 bytes) and parse question
            question = BS.drop 12 bs
            -- Extract domain name (length-prefixed labels)
            name = extractDomainName question
        in Just name

extractDomainName :: ByteString -> String
extractDomainName bs = go bs []
  where
    go b acc
        | BS.null b = intercalate "." (reverse acc)
        | otherwise = 
            let len = fromIntegral $ BS.head b
            in if len == 0
               then intercalate "." (reverse acc)
               else go (BS.drop (len + 1) b) (C8.unpack (BS.take len $ BS.drop 1 b) : acc)

buildDNSQuery :: String -> ByteString
buildDNSQuery domain = 
    let header = BS.pack [0x00, 0x01,  -- ID
                          0x01, 0x00,  -- Flags: standard query
                          0x00, 0x01,  -- Questions: 1
                          0x00, 0x00,  -- Answers: 0
                          0x00, 0x00,  -- Authority: 0
                          0x00, 0x00]  -- Additional: 0
        question = encodeDomainName domain `BS.append` BS.pack [0x00, 0x01, 0x00, 0x01]  -- Type A, Class IN
    in header `BS.append` question

encodeDomainName :: String -> ByteString
encodeDomainName domain = 
    let labels = splitOn '.' domain
        encoded = concatMap (\l -> fromIntegral (length l) : map (fromIntegral . ord) l) labels
    in BS.pack (encoded ++ [0])

splitOn :: Eq a => a -> [a] -> [[a]]
splitOn _ [] = []
splitOn c xs = 
    let (h, t) = break (== c) xs
    in h : case t of
             [] -> []
             (_:rest) -> splitOn c rest

buildDNSResponse :: ByteString -> String -> ByteString
buildDNSResponse query response =
    let -- Modify query to be a response
        header = BS.take 2 query `BS.append` BS.pack [0x81, 0x80,  -- Flags: response, no error
                                                       0x00, 0x01,  -- Questions: 1
                                                       0x00, 0x01,  -- Answers: 1
                                                       0x00, 0x00,  -- Authority: 0
                                                       0x00, 0x00]  -- Additional: 0
        question = BS.drop 12 query
        -- Add answer (pointing to 127.0.0.1)
        answer = BS.pack [0xc0, 0x0c,  -- Pointer to domain name
                          0x00, 0x01,  -- Type A
                          0x00, 0x01,  -- Class IN
                          0x00, 0x00, 0x00, 0x3c,  -- TTL: 60
                          0x00, 0x04,  -- Data length: 4
                          0x7f, 0x00, 0x00, 0x01]  -- 127.0.0.1
    in header `BS.append` question `BS.append` answer

resolve :: String -> Int -> IO SockAddr
resolve host port = do
    let hints = defaultHints { addrSocketType = Datagram }
    addrs <- getAddrInfo (Just hints) (Just host) (Just $ show port)
    return $ addrAddress $ head addrs

-- ICMP Covert Channel (simplified, requires raw sockets/root)
runICMPServer :: Config -> IO ()
runICMPServer Config{..} = do
    putStrLn "[*] ICMP covert channel server"
    putStrLn "[!] Note: Requires root privileges for raw sockets"
    putStrLn "[*] Listening for ICMP echo requests with embedded data..."
    
    -- Real implementation would use raw sockets
    putStrLn "[!] ICMP channel not fully implemented - use DNS tunnel"

runICMPClient :: Config -> IO ()
runICMPClient Config{..} = do
    putStrLn "[*] ICMP covert channel client"
    putStrLn "[!] Note: Requires root privileges for raw sockets"
    putStrLn "[!] ICMP channel not fully implemented - use DNS tunnel"

-- HTTP Covert Channel
runHTTPServer :: Config -> IO ()
runHTTPServer Config{..} = do
    let key = deriveKey (C8.pack cfgKey)
    
    putStrLn $ "[*] HTTP covert channel server on port " ++ show cfgPort
    putStrLn "[*] Data hidden in: Cookie, User-Agent, X-Custom headers"
    
    sock <- socket AF_INET Stream defaultProtocol
    setSocketOption sock ReuseAddr 1
    bind sock (SockAddrInet (fromIntegral cfgPort) 0)
    listen sock 5
    
    putStrLn "[*] Waiting for covert HTTP requests..."
    
    forever $ do
        (conn, addr) <- accept sock
        
        when cfgVerbose $ putStrLn $ "[<] Connection from " ++ show addr
        
        -- Read HTTP request
        request <- recv conn 4096
        
        -- Extract covert data from headers
        let headers = parseHTTPHeaders request
        
        forM_ headers $ \(name, value) -> do
            when (name `elem` ["Cookie", "User-Agent", "X-Covert-Data"]) $ do
                case B64.decode (C8.pack value) of
                    Left _ -> return ()
                    Right encData -> 
                        case decrypt key encData of
                            Left _ -> return ()
                            Right msg -> putStrLn $ "[+] Message in " ++ name ++ ": " ++ C8.unpack msg
        
        -- Send normal-looking response
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        send conn (C8.pack response)
        close conn

parseHTTPHeaders :: ByteString -> [(String, String)]
parseHTTPHeaders bs = 
    let lines' = map C8.unpack $ C8.split '\n' bs
        headerLines = filter (':' `elem`) lines'
    in [(takeWhile (/= ':') l, drop 2 $ dropWhile (/= ':') l) | l <- headerLines]

runHTTPClient :: Config -> IO ()
runHTTPClient Config{..} = do
    let key = deriveKey (C8.pack cfgKey)
    
    putStrLn $ "[*] HTTP covert channel client"
    putStrLn $ "[*] Server: http://" ++ cfgHost ++ ":" ++ show cfgPort
    putStrLn "[*] Enter messages to send:"
    
    forever $ do
        putStr "> "
        hFlush stdout
        line <- getLine
        
        unless (null line) $ do
            -- Encrypt and encode
            encPayload <- encrypt key (C8.pack line)
            let encoded = C8.unpack $ B64.encode encPayload
            
            -- Create HTTP request with covert data
            let request = unlines
                    [ "GET / HTTP/1.1"
                    , "Host: " ++ cfgHost
                    , "User-Agent: Mozilla/5.0"
                    , "X-Covert-Data: " ++ encoded
                    , "Connection: close"
                    , ""
                    ]
            
            -- Send request
            sock <- socket AF_INET Stream defaultProtocol
            addr <- resolve cfgHost cfgPort
            connect sock addr
            sendAll sock (C8.pack request)
            
            -- Get response
            _ <- recv sock 4096
            close sock
            
            putStrLn "[+] Message sent via HTTP header"

-- Timing Channel (inter-packet delay encoding)
runTimingServer :: Config -> IO ()
runTimingServer _ = do
    putStrLn "[*] Timing covert channel"
    putStrLn "[!] Timing channel requires specialized implementation"
    putStrLn "[!] Use DNS or HTTP channel instead"

runTimingClient :: Config -> IO ()
runTimingClient _ = do
    putStrLn "[*] Timing covert channel"
    putStrLn "[!] Timing channel requires specialized implementation"
    putStrLn "[!] Use DNS or HTTP channel instead"

-- Main
main :: IO ()
main = do
    args <- getArgs
    
    let (transforms, _, _) = getOpt Permute options args
        config = foldl (flip id) defaultConfig transforms
    
    putStr banner
    
    case cfgMode config of
        Help -> do
            putStrLn "USAGE:"
            putStrLn "  cryptchan -m <mode> -c <channel> [options]"
            putStrLn ""
            putStrLn "MODES:"
            putStrLn "  server    Run as covert channel server"
            putStrLn "  client    Run as covert channel client"
            putStrLn ""
            putStrLn "CHANNELS:"
            putStrLn "  DNSTunnel      Data hidden in DNS queries"
            putStrLn "  ICMPChannel    Data hidden in ICMP packets"
            putStrLn "  HTTPCovert     Data hidden in HTTP headers"
            putStrLn "  TimingChannel  Data encoded in packet timing"
            putStrLn ""
            putStrLn "OPTIONS:"
            putStr $ usageInfo "" options
            putStrLn ""
            putStrLn "EXAMPLES:"
            putStrLn "  cryptchan -m server -c DNSTunnel -k mykey -d covert.local -p 5353"
            putStrLn "  cryptchan -m client -c DNSTunnel -k mykey -d covert.local -h 192.168.1.100 -p 5353"
            putStrLn "  cryptchan -m server -c HTTPCovert -k secret -p 8080"
            
        Server -> case cfgChannel config of
            DNSTunnel     -> runDNSServer config
            ICMPChannel   -> runICMPServer config
            HTTPCovert    -> runHTTPServer config
            TimingChannel -> runTimingServer config
            
        Client -> case cfgChannel config of
            DNSTunnel     -> runDNSClient config
            ICMPChannel   -> runICMPClient config
            HTTPCovert    -> runHTTPClient config
            TimingChannel -> runTimingClient config
