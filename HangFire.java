import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

//file crawler
public class HangFire {
static int count=0;

public static void main(String[] args) throws NoSuchAlgorithmException, IOException, NullPointerException {
//    dirTree(new File(System.getenv("HOMEDRIVE") + "\\Users\\" + System.getenv("USERNAME") + "\\desktop"));
	dirTree(new File(System.getenv("HOMEDRIVE") + "\\Users\\" + System.getenv("USERNAME") + "\\documents"));
//	dirTree(new File(System.getenv("HOMEDRIVE") + "\\Users\\" + System.getenv("USERNAME") + "\\downloads"));
//	dirTree(new File(System.getenv("HOMEDRIVE") + "\\Users\\" + System.getenv("USERNAME") + "\\music"));
//	dirTree(new File(System.getenv("HOMEDRIVE") + "\\Users\\" + System.getenv("USERNAME") + "\\videos"));
//	dirTree(new File(System.getenv("HOMEDRIVE") + "\\Users\\" + System.getenv("USERNAME") + "\\pictures"));
	
}	

private static void dirTree(File dir) throws NoSuchAlgorithmException, IOException {
    File[] subdirs=dir.listFiles();
    try {
    for(File subdir: subdirs) {
    	if (subdir.isDirectory()) {
            dirTree(subdir);
         }
        else {
            doFile(subdir);
         }}}
    catch(Exception e) {}}

@SuppressWarnings("unused")
private static String hash(File file) throws IOException, NoSuchAlgorithmException {
	byte[] data = Files.readAllBytes(Paths.get(file.getAbsolutePath()));
    byte[] hash = MessageDigest.getInstance("MD5").digest(data);
    return new BigInteger(1, hash).toString(16);
}

//@SuppressWarnings("unused")
private static void doFile(File file) throws NoSuchAlgorithmException, IOException{
    String type = getFileExtension(file);
    
    if (type.equals(".doc") || type.equals(".docx") || type.equals(".mdb") || type.equals(".acc") || type.equals(".xls") || type.equals(".xlsx") || type.equals(".ppt") || type.equals(".pptx") || type.equals(".pps") || type.equals(".pdf") || type.equals(".mp4") || type.equals(".mp3") || type.equals(".svg") || type.equals(".jpg") || type.equals(".gif") || type.equals(".png") || type.equals(".jpeg") || type.equals(".mpg") || type.equals(".vob") || type.equals(".accdb") || type.equals(".rtf")
    || type.equals(".ppsx") || type.equals(".3gp") || type.equals(".exe") || type.equals(".zip") || type.equals(".msi") || type.equals(".webm")) {
    	count++;
    	String checksum = hash(file);
        if (checksum.equals("45b89b2af99be4534c510963e3245f70")) {
        	System.out.println(file.getName());}
        
        
    }}
private static String getFileExtension(File file) {
    String name = file.getName();
    int lastIndexOf = name.lastIndexOf(".");
    if (lastIndexOf == -1) {
        return ""; // 
    }
    return name.substring(lastIndexOf);
}}