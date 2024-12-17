/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package scard;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Vu Tuan Anh
 */
public class MySQLConnect {

    // init database constants
    private static final String DATABASE_URL = "jdbc:mysql://localhost:3306/theravaocongty";
    private static final String USER = "root";
    private static final String PASSWORD = "";

    private static Connection con;

    public static Connection getConnection() {
        con = null;
        try {
            DriverManager.registerDriver(new com.mysql.cj.jdbc.Driver());
            con = (Connection) DriverManager.getConnection(DATABASE_URL, USER, PASSWORD);
        } catch (SQLException ex) {
            System.out.println("Lỗi khi kết nối DATABASE: " + ex);
        }
        return (con);
    }

    public static void closeConnection() {
        try {
            con.close();
        } catch (SQLException ex) {
            System.out.println("Lỗi khi đóng DATABASE: " + ex);
        }
    }

    public static int saveToDatabase(String manv, String publickey, String checkin, String checkout) {
        try {
            String str = "INSERT INTO card (manv, publickey, checkin, checkout)"
                    + "VALUES(?,?,?,?)";
            PreparedStatement pst = con.prepareStatement(str);
            pst.setString(1, manv);
            pst.setString(2, publickey);
            pst.setString(3, checkin);
            pst.setString(4, checkout);
            pst.execute();
            return 1; // insert thành công
        } catch (Exception e) {
            System.out.println("Lỗi khi lưu dữ liệu vào database: " + e);
            return 0;
        }
    }

    public static List queryDatabase(String manv) {
        List list = new ArrayList<>();
        try {
            String sqlQuery = "SELECT * FROM card WHERE manv = ?";
            PreparedStatement ps = con.prepareStatement(sqlQuery);
            ps.setString(1, manv);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                String publicKey = rs.getString("publickey");
                String checkIn = rs.getString("checkin");
                String checkOut = rs.getString("checkout");
                list.add(manv);
                list.add(publicKey);
                list.add(checkIn);
                list.add(checkOut);
            }
            ps.close();
        } catch (Exception e) {
            System.out.println("Lỗi khi truy vấn dữ liệu từ database: " + e);
        }
        return list;
    }

    public static int setTimeCheck(boolean isCheckIn, String manv, String time) {
        try {
            String query = isCheckIn ? "UPDATE card set checkin = ? WHERE manv = ?" : "UPDATE card set checkout = ? WHERE manv = ?";
            PreparedStatement pst = con.prepareStatement(query);
            pst.setString(1, time);
            pst.setString(2, manv);
            pst.execute();
            return 1;
        } catch (Exception e) {
            return 0;
        }
    }
}
