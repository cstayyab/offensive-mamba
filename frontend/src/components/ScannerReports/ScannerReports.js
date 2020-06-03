import React, { Component } from 'react';
import { Container, Row, Col } from 'reactstrap'
import ScannerSummary from './ScannerSummary'
import ScannerSingleSystem from './ScannerSingleSystem'
import API from '../../api'
class ScannerReports extends Component {
    constructor(props) {
        super(props)
        this.state = {'systems': []}
    }
    async componentDidMount() {
        await this.getLocalSystems()
        
    }

    async getLocalSystems() {
        var response = await API.getAllLocalSystems()
        if(response.success) {
            this.setState({'systems': response.data})
        } else {
            this.setState({'systems': []})
        }
    }

    render() {
        return (
            <Container fluid={"true"}>
                <Row>
                    <Col>
                        <h1 className="border-bottom">Scanner Reports</h1>
                        <div><small>View scanning information of your systems</small></div>
                    </Col>
                </Row>
                <Container className="main">
                    <ScannerSummary />
                    <hr />
                    {(this.state.systems) ? <h2 class="border-bottom">Ports Data</h2> : null}
                    {
                        (this.state.systems)  ? this.state.systems.map((ipaddress, i) => {
                            return (<><ScannerSingleSystem ipaddress={ipaddress} /></>)
                        }) : null
                    }
                </Container>
            </Container>
        )
    }

}



export default ScannerReports