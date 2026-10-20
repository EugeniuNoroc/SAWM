package com.lab.model;

public class Guest {
    private int id;
    private String user;
    private String textMessage;
    private String eMail;
    private String dataTimeMessage;

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getUser() { return user; }
    public void setUser(String user) { this.user = user; }

    public String getTextMessage() { return textMessage; }
    public void setTextMessage(String textMessage) { this.textMessage = textMessage; }

    public String geteMail() { return eMail; }
    public void seteMail(String eMail) { this.eMail = eMail; }

    public String getDataTimeMessage() { return dataTimeMessage; }
    public void setDataTimeMessage(String dataTimeMessage) { this.dataTimeMessage = dataTimeMessage; }
}
