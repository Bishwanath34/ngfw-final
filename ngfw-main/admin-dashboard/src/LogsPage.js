import React, { useEffect, useState } from "react";
import axios from "axios";
import {
  Table, TableBody, TableCell, TableContainer,
  TableHead, TableRow, Paper, Chip, Typography
} from "@mui/material";

export default function LogsPage() {
  const [logs, setLogs] = useState([]);

  // Load logs every 2 seconds
  const loadLogs = async () => {
    try {
      const res = await axios.get("http://localhost:4000/admin/logs");
      setLogs(res.data.slice().reverse());
    } catch (err) {
      console.error("Error loading logs:", err);
    }
  };

  useEffect(() => {
    loadLogs();
    const timer = setInterval(loadLogs, 2000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div style={{ padding: 20 }}>
      <Typography variant="h4" gutterBottom>
        Firewall Traffic Logs
      </Typography>

      <TableContainer component={Paper} sx={{ backgroundColor: "#111" }}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell sx={{ color: "white" }}>Time</TableCell>
              <TableCell sx={{ color: "white" }}>Path</TableCell>
              <TableCell sx={{ color: "white" }}>User</TableCell>
              <TableCell sx={{ color: "white" }}>Role</TableCell>
              <TableCell sx={{ color: "white" }}>Risk</TableCell>
              <TableCell sx={{ color: "white" }}>Decision</TableCell>
              <TableCell sx={{ color: "white" }}>Status</TableCell>
            </TableRow>
          </TableHead>

          <TableBody>
            {logs.map((entry, index) => (
              <TableRow key={index}>
                <TableCell sx={{ color: "#ddd" }}>{entry.time}</TableCell>
                <TableCell sx={{ color: "#ddd" }}>{entry.context.path}</TableCell>
                <TableCell sx={{ color: "#ddd" }}>{entry.context.userId}</TableCell>
                <TableCell sx={{ color: "#ddd" }}>{entry.context.role}</TableCell>

                <TableCell>
                  <Chip
                    label={entry.decision.label}
                    color={
                      entry.decision.label === "high_risk" ? "error" :
                      entry.decision.label === "medium_risk" ? "warning" :
                      "success"
                    }
                  />
                </TableCell>

                <TableCell>
                  {entry.decision.allow ? (
                    <Chip label="Allowed" color="success" />
                  ) : (
                    <Chip label="Blocked" color="error" />
                  )}
                </TableCell>

                <TableCell sx={{ color: "#ddd" }}>{entry.statusCode}</TableCell>
              </TableRow>
            ))}
          </TableBody>

        </Table>
      </TableContainer>
    </div>
  );
}
