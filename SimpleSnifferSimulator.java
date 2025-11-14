import javax.swing.*;
import java.awt.*;
import java.util.LinkedList;
import java.util.Queue;

/* ================= PACKET INTERFACE ================= */

interface NetworkProtocol { void analyze(); }

/* ================= PACKET CLASSES ================= */

abstract class BasePacket implements NetworkProtocol {
    protected String src, dest, proto, payload;
    protected JTextArea out;

    public BasePacket(String s,String d,String p,String pay,JTextArea o){
        src=s; dest=d; proto=p; payload=pay; out=o;
    }

    protected void log(String msg){
        out.append(msg+"\n");
        out.setCaretPosition(out.getDocument().getLength());
    }

    public void showInfo(){
        log("[IP] Src: "+src+" | Dest: "+dest+" | Proto: "+proto);
    }
}

class TCPPacket extends BasePacket {
    int port;
    public TCPPacket(String s,String d,String pay,int p,JTextArea o){
        super(s,d,"TCP",pay,o); port=p;
    }
    public void analyze(){
        showInfo();
        log("[TCP] Port: "+port+" | Data: "+payload);
    }
}

class UDPPacket extends BasePacket {
    int len;
    public UDPPacket(String s,String d,String pay,int l,JTextArea o){
        super(s,d,"UDP",pay,o); len=l;
    }
    public void analyze(){
        showInfo();
        log("[UDP] Len: "+len+" | Data: "+payload);
    }
}

/* ================= BUFFER ================= */

class PacketBuffer {
    private Queue<NetworkProtocol> q = new LinkedList<>();
    private final int CAP = 5;
    JTextArea out;

    public PacketBuffer(JTextArea o){ out=o; }

    private void log(String s){
        SwingUtilities.invokeLater(() -> out.append(s+"\n"));
    }

    public synchronized void put(NetworkProtocol p) throws InterruptedException {
        while(q.size()==CAP){
            log("[Buffer] FULL — waiting...");
            wait();
        }
        q.add(p);
        log("[Captured] "+((BasePacket)p).proto);
        notifyAll();
    }

    public synchronized NetworkProtocol take() throws InterruptedException {
        while(q.isEmpty()){
            log("[Buffer] EMPTY — waiting...");
            wait();
        }
        NetworkProtocol p=q.poll();
        notifyAll();
        return p;
    }
}

/* ================= CAPTURER THREAD ================= */

class PacketCapturer implements Runnable {
    PacketBuffer buf; JTextArea out; boolean run=true;

    private String randomIP(){
        return (int)(Math.random()*255) + "." +
               (int)(Math.random()*255) + "." +
               (int)(Math.random()*255) + "." +
               (int)(Math.random()*255);
    }

    private String[] randomPacket() {
        String[] payloads = {
            "GET /login", "POST /data", "DNS Query",
            "NTP Sync", "SSH Auth", "MAIL SEND"
        };
        String pay = payloads[(int)(Math.random()*payloads.length)];
        boolean isTCP = Math.random() > 0.5;

        return isTCP ?
            new String[]{ randomIP(), randomIP(), pay, "TCP",
                String.valueOf((int)(Math.random()*60000)+1024) } :
            new String[]{ randomIP(), randomIP(), pay, "UDP",
                String.valueOf((int)(Math.random()*500)+20) };
    }

    public PacketCapturer(PacketBuffer b,JTextArea o){
        buf=b; out=o;
    }

    public void stop(){ run=false; }

    public void run(){
        try{
            while(run){
                String[] d = randomPacket();

                NetworkProtocol pk = d[3].equals("TCP")
                        ? new TCPPacket(d[0],d[1],d[2],Integer.parseInt(d[4]),out)
                        : new UDPPacket(d[0],d[1],d[2],Integer.parseInt(d[4]),out);

                buf.put(pk);
                Thread.sleep(300);
            }
        }catch(Exception ignored){}
    }
}

/* ================= ANALYZER THREAD ================= */

class PacketAnalyzer implements Runnable {
    PacketBuffer buf; JTextArea out; boolean run=true;
    public PacketAnalyzer(PacketBuffer b,JTextArea o){ buf=b; out=o; }
    public void stop(){ run=false; }

    public void run(){
        try{
            while(run){
                NetworkProtocol p = buf.take();

                SwingUtilities.invokeLater(() -> {
                    out.append("\n--- Analysis Start ---\n");
                    p.analyze();
                    out.append("--- Analysis End ---\n");
                });

                Thread.sleep(400);
            }
        }catch(Exception ignored){}
    }
}

/* ================= MAIN GUI ================= */

public class SimpleSnifferSimulator extends JFrame {

    PacketCapturer cap;
    PacketAnalyzer ana;

    public SimpleSnifferSimulator(){
        setTitle("Packet Sniffer Simulator");
        setSize(1100,700);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(EXIT_ON_CLOSE);

        JPanel main = new JPanel(new BorderLayout()){
            protected void paintComponent(Graphics g){
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setPaint(new GradientPaint(
                        0,0,new Color(15,15,40),
                        0,getHeight(),new Color(25,25,60)
                ));
                g2.fillRect(0,0,getWidth(),getHeight());
            }
        };

        JLabel title = new JLabel("NETWORK PACKET SNIFFER SIMULATOR", SwingConstants.CENTER);
        title.setFont(new Font("Segoe UI", Font.BOLD, 38));
        title.setForeground(new Color(125,255,233));
        title.setBorder(BorderFactory.createEmptyBorder(80,0,40,0));

        JButton open = createButton("Open Simulation", new Color(30,144,255));
        JButton exitHome = createButton("Exit", new Color(230,50,50));

        JPanel btnPanel=new JPanel();
        btnPanel.setOpaque(false);
        btnPanel.add(open);
        btnPanel.add(exitHome);

        main.add(title,BorderLayout.CENTER);
        main.add(btnPanel,BorderLayout.SOUTH);

        setContentPane(main);

        open.addActionListener(e -> openSimulation());
        exitHome.addActionListener(e -> System.exit(0));

        setVisible(true);
    }

    /* Helper Button Style */
    private JButton createButton(String text, Color bg){
        JButton b = new JButton(text);
        b.setFont(new Font("Segoe UI", Font.BOLD, 22));
        b.setBackground(bg);
        b.setForeground(Color.WHITE);
        b.setFocusPainted(false);
        b.setPreferredSize(new Dimension(220,60));
        b.setBorder(BorderFactory.createLineBorder(Color.WHITE,3));
        return b;
    }

    /* ================= TCP / UDP WINDOWS WITH EXIT BUTTON ================= */

    private void showFilteredWindow(String type, JTextArea sourceArea){
        JFrame f=new JFrame(type+" Packets");
        f.setSize(650,550);
        f.setLocationRelativeTo(this);

        JPanel panel=new JPanel(new BorderLayout());
        panel.setBackground(new Color(20,20,40));
        f.setContentPane(panel);

        JLabel head=new JLabel(type+" PACKETS ONLY",SwingConstants.CENTER);
        head.setFont(new Font("Segoe UI",Font.BOLD,26));
        head.setForeground(type.equals("TCP") ? new Color(180,120,255) : new Color(255,170,80));
        head.setBorder(BorderFactory.createEmptyBorder(15,0,15,0));
        panel.add(head,BorderLayout.NORTH);

        JTextArea view=new JTextArea();
        view.setFont(new Font("Consolas",15,15));
        view.setForeground(Color.WHITE);
        view.setBackground(new Color(30,30,60));
        view.setEditable(false);

        JScrollPane sp=new JScrollPane(view);
        sp.setBorder(BorderFactory.createLineBorder(
                type.equals("TCP") ? new Color(180,120,255) : new Color(255,170,80),
                3
        ));

        panel.add(sp,BorderLayout.CENTER);

        for(String s : sourceArea.getText().split("\n")){
            if(type.equals("TCP") && s.contains("[TCP")) view.append(s+"\n");
            if(type.equals("UDP") && s.contains("[UDP")) view.append(s+"\n");
        }

        JButton exitBtn = new JButton("Exit");
        exitBtn.setFont(new Font("Segoe UI", Font.BOLD, 16));
        exitBtn.setForeground(Color.WHITE);
        exitBtn.setBackground(new Color(200,40,40));
        exitBtn.setFocusPainted(false);
        exitBtn.setPreferredSize(new Dimension(100,40));
        exitBtn.setBorder(BorderFactory.createLineBorder(Color.WHITE,2));
        exitBtn.addActionListener(e -> f.dispose());

        JPanel bottom = new JPanel();
        bottom.setBackground(new Color(20,20,40));
        bottom.add(exitBtn);

        panel.add(bottom, BorderLayout.SOUTH);

        f.setVisible(true);
    }

    /* ================= SIMULATION WINDOW ================= */

    private void openSimulation(){
        JFrame f=new JFrame("Simulation");
        f.setSize(1200,750);
        f.setLocationRelativeTo(this);

        JPanel root=new JPanel(new BorderLayout());
        root.setBackground(new Color(20,20,40));
        f.setContentPane(root);

        JLabel head=new JLabel("LIVE PACKET SIMULATION",SwingConstants.CENTER);
        head.setFont(new Font("Segoe UI",Font.BOLD,28));
        head.setForeground(new Color(125,255,233));
        head.setBorder(BorderFactory.createEmptyBorder(20,0,20,0));
        root.add(head,BorderLayout.NORTH);

        JTextArea out=new JTextArea();
        out.setFont(new Font("Consolas",15,15));
        out.setForeground(Color.WHITE);
        out.setBackground(new Color(25,25,60));

        JScrollPane sp=new JScrollPane(out);
        root.add(sp,BorderLayout.CENTER);

        JPanel bottom=new JPanel();
        bottom.setBackground(new Color(25,25,50));

        JButton start=createSimButton("Start", new Color(0,200,100));
        JButton stop=createSimButton("Stop", new Color(230,50,50));
        JButton clear=createSimButton("Clear Log", new Color(30,144,255));
        JButton tcp=createSimButton("TCP Logs", new Color(138,43,226));
        JButton udp=createSimButton("UDP Logs", new Color(255,140,0));
        JButton exitSim=createSimButton("Exit Simulation", new Color(200,40,40));

        bottom.add(start);
        bottom.add(stop);
        bottom.add(clear);
        bottom.add(tcp);
        bottom.add(udp);
        bottom.add(exitSim);

        root.add(bottom,BorderLayout.SOUTH);

        start.addActionListener(e -> {
            out.setText("");
            PacketBuffer buf=new PacketBuffer(out);
            cap=new PacketCapturer(buf,out);
            ana=new PacketAnalyzer(buf,out);
            new Thread(cap).start();
            new Thread(ana).start();
        });

        stop.addActionListener(e -> {
            if(cap!=null) cap.stop();
            if(ana!=null) ana.stop();
            out.append("\n=== Simulation Stopped ===\n");
        });

        clear.addActionListener(e -> out.setText(""));

        tcp.addActionListener(e -> showFilteredWindow("TCP", out));
        udp.addActionListener(e -> showFilteredWindow("UDP", out));

        exitSim.addActionListener(e -> f.dispose());

        f.setVisible(true);
    }

    private JButton createSimButton(String text, Color bg){
        JButton b=new JButton(text);
        b.setPreferredSize(new Dimension(150,45));
        b.setForeground(Color.WHITE);
        b.setFont(new Font("Segoe UI",Font.BOLD,15));
        b.setFocusPainted(false);
        b.setBackground(bg);
        b.setBorder(BorderFactory.createLineBorder(Color.WHITE,2));
        return b;
    }

    public static void main(String[] args){
        SwingUtilities.invokeLater(SimpleSnifferSimulator::new);
    }
}
