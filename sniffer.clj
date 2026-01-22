;; NullSec Sniffer - Network Packet Analyzer
;; Language: Clojure
;; Author: bad-antics
;; License: NullSec Proprietary

(ns nullsec.sniffer
  (:require [clojure.string :as str]
            [clojure.java.io :as io])
  (:import [java.net DatagramSocket DatagramPacket InetAddress NetworkInterface]
           [java.nio ByteBuffer ByteOrder]
           [java.util Date]
           [java.text SimpleDateFormat]))

(def version "1.0.0")

(def banner
  "
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░░░ S N I F F E R ░░░░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics v")

;; Protocol numbers
(def protocols
  {1 "ICMP"
   6 "TCP"
   17 "UDP"
   41 "IPv6"
   47 "GRE"
   50 "ESP"
   51 "AH"
   89 "OSPF"})

;; Common ports
(def port-services
  {20 "FTP-DATA"
   21 "FTP"
   22 "SSH"
   23 "TELNET"
   25 "SMTP"
   53 "DNS"
   80 "HTTP"
   110 "POP3"
   143 "IMAP"
   443 "HTTPS"
   445 "SMB"
   993 "IMAPS"
   995 "POP3S"
   3306 "MySQL"
   3389 "RDP"
   5432 "PostgreSQL"
   8080 "HTTP-Alt"})

;; State atoms
(def stats (atom {:packets 0
                  :bytes 0
                  :tcp 0
                  :udp 0
                  :icmp 0
                  :other 0
                  :start-time nil}))

(def captured-creds (atom []))

;; Utility functions
(defn timestamp []
  (.format (SimpleDateFormat. "HH:mm:ss.SSS") (Date.)))

(defn log-msg [verbose msg]
  (when verbose
    (println (str "[" (timestamp) "] " msg))))

(defn bytes->hex [bytes]
  (str/join " " (map #(format "%02X" (bit-and % 0xFF)) bytes)))

(defn bytes->ascii [bytes]
  (str/join (map #(let [b (bit-and % 0xFF)]
                    (if (and (>= b 32) (<= b 126))
                      (char b)
                      "."))
                 bytes)))

(defn ip->str [ip-bytes]
  (str/join "." (map #(bit-and % 0xFF) ip-bytes)))

;; Packet parsing
(defn parse-ethernet [data]
  (when (>= (count data) 14)
    (let [dest-mac (take 6 data)
          src-mac (take 6 (drop 6 data))
          ethertype (+ (bit-shift-left (bit-and (nth data 12) 0xFF) 8)
                       (bit-and (nth data 13) 0xFF))]
      {:dest-mac (str/join ":" (map #(format "%02X" (bit-and % 0xFF)) dest-mac))
       :src-mac (str/join ":" (map #(format "%02X" (bit-and % 0xFF)) src-mac))
       :ethertype ethertype
       :payload (drop 14 data)})))

(defn parse-ipv4 [data]
  (when (>= (count data) 20)
    (let [version-ihl (bit-and (first data) 0xFF)
          version (bit-shift-right version-ihl 4)
          ihl (bit-and version-ihl 0x0F)
          header-len (* ihl 4)
          total-len (+ (bit-shift-left (bit-and (nth data 2) 0xFF) 8)
                       (bit-and (nth data 3) 0xFF))
          protocol (bit-and (nth data 9) 0xFF)
          src-ip (take 4 (drop 12 data))
          dest-ip (take 4 (drop 16 data))]
      {:version version
       :header-len header-len
       :total-len total-len
       :protocol protocol
       :protocol-name (get protocols protocol "UNKNOWN")
       :src-ip (ip->str src-ip)
       :dest-ip (ip->str dest-ip)
       :payload (drop header-len data)})))

(defn parse-tcp [data]
  (when (>= (count data) 20)
    (let [src-port (+ (bit-shift-left (bit-and (nth data 0) 0xFF) 8)
                      (bit-and (nth data 1) 0xFF))
          dest-port (+ (bit-shift-left (bit-and (nth data 2) 0xFF) 8)
                       (bit-and (nth data 3) 0xFF))
          seq-num (+ (bit-shift-left (bit-and (nth data 4) 0xFF) 24)
                     (bit-shift-left (bit-and (nth data 5) 0xFF) 16)
                     (bit-shift-left (bit-and (nth data 6) 0xFF) 8)
                     (bit-and (nth data 7) 0xFF))
          data-offset (bit-shift-right (bit-and (nth data 12) 0xFF) 4)
          header-len (* data-offset 4)
          flags (bit-and (nth data 13) 0xFF)]
      {:src-port src-port
       :src-service (get port-services src-port)
       :dest-port dest-port
       :dest-service (get port-services dest-port)
       :seq-num seq-num
       :header-len header-len
       :flags {:fin (bit-test flags 0)
               :syn (bit-test flags 1)
               :rst (bit-test flags 2)
               :psh (bit-test flags 3)
               :ack (bit-test flags 4)
               :urg (bit-test flags 5)}
       :payload (drop header-len data)})))

(defn parse-udp [data]
  (when (>= (count data) 8)
    (let [src-port (+ (bit-shift-left (bit-and (nth data 0) 0xFF) 8)
                      (bit-and (nth data 1) 0xFF))
          dest-port (+ (bit-shift-left (bit-and (nth data 2) 0xFF) 8)
                       (bit-and (nth data 3) 0xFF))
          length (+ (bit-shift-left (bit-and (nth data 4) 0xFF) 8)
                    (bit-and (nth data 5) 0xFF))]
      {:src-port src-port
       :src-service (get port-services src-port)
       :dest-port dest-port
       :dest-service (get port-services dest-port)
       :length length
       :payload (drop 8 data)})))

(defn parse-dns [data]
  (when (>= (count data) 12)
    (let [id (+ (bit-shift-left (bit-and (nth data 0) 0xFF) 8)
                (bit-and (nth data 1) 0xFF))
          flags (+ (bit-shift-left (bit-and (nth data 2) 0xFF) 8)
                   (bit-and (nth data 3) 0xFF))
          qr (bit-test flags 15)
          qdcount (+ (bit-shift-left (bit-and (nth data 4) 0xFF) 8)
                     (bit-and (nth data 5) 0xFF))]
      {:id id
       :is-response qr
       :questions qdcount})))

;; Credential detection
(def credential-patterns
  [;; HTTP Basic Auth
   {:name "HTTP Basic Auth"
    :pattern #"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)"
    :decoder (fn [match]
               (try
                 (let [decoded (String. (.decode (java.util.Base64/getDecoder) (second match)))]
                   (str "Credentials: " decoded))
                 (catch Exception _ nil)))}
   ;; FTP credentials
   {:name "FTP USER"
    :pattern #"USER\s+(\S+)"
    :decoder (fn [match] (str "Username: " (second match)))}
   {:name "FTP PASS"
    :pattern #"PASS\s+(\S+)"
    :decoder (fn [match] (str "Password: " (second match)))}
   ;; SMTP/POP3
   {:name "AUTH LOGIN"
    :pattern #"AUTH\s+LOGIN"
    :decoder (fn [_] "AUTH LOGIN detected")}
   ;; HTTP Form data
   {:name "HTTP Form"
    :pattern #"(?:password|passwd|pwd|pass)=([^&\s]+)"
    :decoder (fn [match] (str "Form password: " (second match)))}])

(defn detect-credentials [payload src-ip dest-ip src-port dest-port]
  (let [data-str (bytes->ascii payload)]
    (doseq [pattern credential-patterns]
      (when-let [match (re-find (:pattern pattern) data-str)]
        (let [cred {:timestamp (timestamp)
                    :type (:name pattern)
                    :src-ip src-ip
                    :dest-ip dest-ip
                    :src-port src-port
                    :dest-port dest-port
                    :data ((:decoder pattern) match)}]
          (swap! captured-creds conj cred)
          (println (str "\n[!] CREDENTIAL DETECTED: " (:name pattern)))
          (println (str "    " (:data cred))))))))

;; Packet display
(defn display-packet [pkt verbose]
  (let [{:keys [protocol-name src-ip dest-ip]} (:ip pkt)]
    (case protocol-name
      "TCP" (let [{:keys [src-port dest-port flags]} (:tcp pkt)
                  flag-str (str/join "" (filter identity
                                                [(when (:syn flags) "S")
                                                 (when (:ack flags) "A")
                                                 (when (:fin flags) "F")
                                                 (when (:rst flags) "R")
                                                 (when (:psh flags) "P")]))]
              (printf "[%s] TCP %s:%d -> %s:%d [%s]%n"
                      (timestamp) src-ip src-port dest-ip dest-port flag-str))
      "UDP" (let [{:keys [src-port dest-port]} (:udp pkt)]
              (printf "[%s] UDP %s:%d -> %s:%d%n"
                      (timestamp) src-ip src-port dest-ip dest-port))
      "ICMP" (printf "[%s] ICMP %s -> %s%n" (timestamp) src-ip dest-ip)
      (printf "[%s] %s %s -> %s%n" (timestamp) protocol-name src-ip dest-ip))))

;; Statistics
(defn update-stats [pkt]
  (let [proto (get-in pkt [:ip :protocol-name])]
    (swap! stats update :packets inc)
    (swap! stats update :bytes + (or (get-in pkt [:ip :total-len]) 0))
    (case proto
      "TCP" (swap! stats update :tcp inc)
      "UDP" (swap! stats update :udp inc)
      "ICMP" (swap! stats update :icmp inc)
      (swap! stats update :other inc))))

(defn print-stats []
  (let [s @stats
        duration (if (:start-time s)
                   (/ (- (System/currentTimeMillis) (:start-time s)) 1000.0)
                   0)]
    (println "\n=== Capture Statistics ===")
    (println (str "Duration: " (format "%.1f" duration) " seconds"))
    (println (str "Total packets: " (:packets s)))
    (println (str "Total bytes: " (:bytes s)))
    (println (str "Packets/sec: " (format "%.1f" (if (> duration 0) (/ (:packets s) duration) 0))))
    (println (str "TCP: " (:tcp s) " | UDP: " (:udp s) " | ICMP: " (:icmp s) " | Other: " (:other s)))))

;; Simulated capture (actual capture would need native libs)
(defn simulate-packet []
  (let [protocols ["TCP" "UDP" "ICMP"]
        proto (rand-nth protocols)
        src-ip (str (+ 1 (rand-int 254)) "." (rand-int 256) "." (rand-int 256) "." (+ 1 (rand-int 254)))
        dest-ip (str (+ 1 (rand-int 254)) "." (rand-int 256) "." (rand-int 256) "." (+ 1 (rand-int 254)))
        src-port (+ 1024 (rand-int 64000))
        dest-port (rand-nth [22 80 443 8080 3306])]
    {:ip {:protocol-name proto
          :src-ip src-ip
          :dest-ip dest-ip
          :total-len (+ 40 (rand-int 1400))}
     :tcp {:src-port src-port
           :dest-port dest-port
           :flags {:syn (< (rand) 0.1)
                   :ack (> (rand) 0.3)
                   :fin (< (rand) 0.05)
                   :rst (< (rand) 0.02)
                   :psh (> (rand) 0.5)}}
     :udp {:src-port src-port
           :dest-port dest-port}}))

(defn capture [options]
  (let [{:keys [interface filter output count extract-creds verbose]} options]
    (println (str "[*] Starting capture on interface: " (or interface "any")))
    (when filter (println (str "[*] BPF Filter: " filter)))
    (when output (println (str "[*] Saving to: " output)))
    (when count (println (str "[*] Capturing " count " packets")))
    (println "[*] Press Ctrl+C to stop")
    (println)
    
    (swap! stats assoc :start-time (System/currentTimeMillis))
    
    ;; Note: Actual packet capture would require:
    ;; - Native pcap library (jnetpcap, pcap4j)
    ;; - Raw socket access
    ;; This is a simulation for demonstration
    
    (println "[!] Running in simulation mode (requires pcap library for real capture)")
    (println)
    
    (let [packets (atom 0)]
      (try
        (loop []
          (when (or (nil? count) (< @packets count))
            (let [pkt (simulate-packet)]
              (display-packet pkt verbose)
              (update-stats pkt)
              (swap! packets inc)
              (Thread/sleep (+ 50 (rand-int 200)))
              (recur))))
        (catch InterruptedException _
          (println "\n[*] Capture interrupted")))
      
      (print-stats)
      
      (when (and extract-creds (seq @captured-creds))
        (println "\n=== Captured Credentials ===")
        (doseq [cred @captured-creds]
          (println (str (:timestamp cred) " | " (:type cred) " | " (:data cred))))))))

(defn analyze [options]
  (let [{:keys [file verbose]} options]
    (println (str "[*] Analyzing file: " file))
    (if (.exists (io/file file))
      (do
        (println "[*] PCAP analysis would process the file here")
        (println "[!] Requires pcap library for actual analysis"))
      (println "[!] File not found"))))

(defn list-interfaces []
  (println "[*] Available network interfaces:")
  (doseq [iface (enumeration-seq (NetworkInterface/getNetworkInterfaces))]
    (when-not (.isLoopback iface)
      (println (str "  - " (.getName iface) " (" (.getDisplayName iface) ")")))))

;; CLI parsing
(defn parse-args [args]
  (loop [args args
         opts {}]
    (if (empty? args)
      opts
      (let [[arg & rest] args]
        (case arg
          ("-i" "--interface") (recur (rest rest) (assoc opts :interface (first rest)))
          ("-f" "--filter") (recur (rest rest) (assoc opts :filter (first rest)))
          ("-o" "--output") (recur (rest rest) (assoc opts :output (first rest)))
          ("-c" "--count") (recur (rest rest) (assoc opts :count (Integer/parseInt (first rest))))
          ("--extract-creds") (recur rest (assoc opts :extract-creds true))
          ("--stats") (recur rest (assoc opts :stats true))
          ("-v" "--verbose") (recur rest (assoc opts :verbose true))
          "capture" (recur rest (assoc opts :command :capture))
          "analyze" (recur rest (assoc opts :command :analyze))
          "interfaces" (recur rest (assoc opts :command :interfaces))
          (recur rest opts))))))

(defn print-usage []
  (println "
USAGE:
    sniffer <command> [options]

COMMANDS:
    capture         Start packet capture
    analyze         Analyze PCAP file
    interfaces      List network interfaces

OPTIONS:
    -i, --interface     Network interface
    -f, --filter        BPF filter expression
    -o, --output        Output file (PCAP)
    -c, --count         Number of packets
    --extract-creds     Extract credentials
    --stats             Show statistics
    -v, --verbose       Verbose output

EXAMPLES:
    sniffer capture -i eth0 -c 100
    sniffer capture -i eth0 -f \"tcp port 80\" --extract-creds
    sniffer analyze -f capture.pcap
"))

(defn -main [& args]
  (println banner version)
  (println)
  
  (if (empty? args)
    (print-usage)
    (let [opts (parse-args args)]
      (case (:command opts)
        :capture (capture opts)
        :analyze (analyze opts)
        :interfaces (list-interfaces)
        (print-usage)))))

;; Entry point for script execution
(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))

;; For clj execution
(when *command-line-args*
  (apply -main *command-line-args*))
